use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct BoundedMap<K, V> {
    entries: BTreeMap<K, Entry<V>>,
    order: BTreeMap<u64, K>,
    capacity: usize,
    next_seq: u64,
}

#[derive(Debug, Clone)]
struct Entry<V> {
    value: V,
    seq: u64,
}

impl<K, V> BoundedMap<K, V>
where
    K: Ord + Clone,
{
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity,
            order: BTreeMap::new(),
            next_seq: 0,
        }
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|entry| &entry.value)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key).map(|entry| &mut entry.value)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(key, entry)| (key, &entry.value))
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.values().map(|entry| &entry.value)
    }

    pub fn insert(&mut self, key: K, value: V) -> Vec<(K, V)> {
        if let Some(existing) = self.entries.remove(&key) {
            self.order.remove(&existing.seq);
        }
        let seq = self.reserve_seq();
        self.order.insert(seq, key.clone());
        self.entries.insert(key, Entry { value, seq });
        self.evict_over_capacity()
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let entry = self.entries.remove(key)?;
        self.order.remove(&entry.seq);
        Some(entry.value)
    }

    pub fn retain<F>(&mut self, mut keep: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        let mut removed = Vec::new();
        self.entries.retain(|key, entry| {
            let keep_entry = keep(key, &mut entry.value);
            if !keep_entry {
                removed.push(entry.seq);
            }
            keep_entry
        });
        for seq in removed {
            self.order.remove(&seq);
        }
    }

    fn evict_over_capacity(&mut self) -> Vec<(K, V)> {
        let mut evicted = Vec::new();
        while self.entries.len() > self.capacity {
            let Some((seq, key)) = self
                .order
                .first_key_value()
                .map(|(seq, key)| (*seq, key.clone()))
            else {
                break;
            };
            self.order.remove(&seq);
            if let Some(entry) = self.entries.remove(&key) {
                evicted.push((key, entry.value));
            }
        }
        evicted
    }

    fn reserve_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        if self.next_seq == 0 {
            self.resequence();
        }
        seq
    }

    fn resequence(&mut self) {
        let mut seq = 0_u64;
        let mut new_order = BTreeMap::new();
        for (_, key) in std::mem::take(&mut self.order) {
            if let Some(entry) = self.entries.get_mut(&key) {
                entry.seq = seq;
                new_order.insert(seq, key);
                seq = seq.saturating_add(1);
            }
        }
        self.order = new_order;
        self.next_seq = seq;
    }
}

#[cfg(test)]
mod tests {
    use super::BoundedMap;

    #[test]
    fn evicts_oldest_entry_over_capacity() {
        let mut map = BoundedMap::new(2);
        assert!(map.insert("a", 1).is_empty());
        assert!(map.insert("b", 2).is_empty());

        let evicted = map.insert("c", 3);

        assert_eq!(evicted, vec![("a", 1)]);
        assert_eq!(map.get(&"b"), Some(&2));
        assert_eq!(map.get(&"c"), Some(&3));
    }

    #[test]
    fn replacing_entry_refreshes_order() {
        let mut map = BoundedMap::new(2);
        map.insert("a", 1);
        map.insert("b", 2);
        map.insert("a", 3);

        let evicted = map.insert("c", 4);

        assert_eq!(evicted, vec![("b", 2)]);
        assert_eq!(map.get(&"a"), Some(&3));
        assert_eq!(map.get(&"c"), Some(&4));
    }
}
