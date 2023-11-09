use serde_json::Value;

pub fn merge(a: &mut Value, b: &Value) {
    match (a, b) {
        (a @ &mut Value::Object(_), Value::Object(b)) => {
            // here `as_object_mut` can not go wrong
            let a = a.as_object_mut().unwrap();
            for (k, v) in b {
                merge(a.entry(k).or_insert(Value::Null), v);
            }
        }
        (a, b) => *a = b.to_owned(),
    }
}
