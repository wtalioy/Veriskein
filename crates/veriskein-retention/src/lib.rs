use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone)]
pub struct BoundedMap<K, V> {
    entries: BTreeMap<K, V>,
    order: VecDeque<K>,
    capacity: usize,
}

impl<K, V> BoundedMap<K, V>
where
    K: Ord + Clone,
{
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter()
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.values()
    }

    pub fn insert(&mut self, key: K, value: V) -> Vec<(K, V)> {
        self.remove_order_entry(&key);
        self.order.push_back(key.clone());
        self.entries.insert(key, value);
        self.evict_over_capacity()
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.remove_order_entry(key);
        self.entries.remove(key)
    }

    pub fn retain<F>(&mut self, mut keep: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        self.entries.retain(|key, value| keep(key, value));
        self.order.retain(|key| self.entries.contains_key(key));
    }

    fn evict_over_capacity(&mut self) -> Vec<(K, V)> {
        let mut evicted = Vec::new();
        while self.entries.len() > self.capacity {
            let Some(key) = self.order.pop_front() else {
                break;
            };
            if let Some(value) = self.entries.remove(&key) {
                evicted.push((key, value));
            }
        }
        evicted
    }

    fn remove_order_entry(&mut self, key: &K) {
        self.order.retain(|existing| existing != key);
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
