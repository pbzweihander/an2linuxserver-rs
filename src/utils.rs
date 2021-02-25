use std::collections::HashMap;

/// Convert HashMap into values vector.
/// Remove when HashMap::into_values is stabilized (https://doc.rust-lang.org/stable/std/collections/struct.HashMap.html#method.into_values)
pub fn hashmap_into_values<K, V, S>(map: HashMap<K, V, S>) -> Vec<V> {
    map.into_iter().map(|(_, v)| v).collect()
}
