//use base64::{encode, decode};
use serde::{Serialize, Deserialize};
//use serde_json::Result;

#[derive(Serialize, Deserialize, Debug)]
struct Person {
    name: String,
    age: u8,
}

// A tuple struct
#[derive(Serialize, Deserialize, Debug)]
struct Pair(i32, f32);

// A struct with two fields
#[derive(Serialize, Deserialize, Debug)]
struct Point {
    x: f32,
    y: f32,
}

#[derive(Serialize, Deserialize, Debug)]
struct Complex {
    p1: Person,
    p2: Person,
    
    x: Point,
    y: Point,
    
    u: Pair,
    v: Pair,
}

fn main() {
    let c = Complex {
        p1: Person{name: "Alice".to_string(), age: 23},
        p2: Person{name: "Bob".to_string(), age: 34},
        x: Point{x: 0.3, y: 0.4},
        y: Point{x: 13.4, y: 16.7},
        u: Pair(10, 20.0),
        v: Pair(44, 55.0)
    };

    println!("{:?}", c);
    let json = serde_json::to_string(&c).unwrap();
    println!("{}", json);
    let base64str = base64::encode(&json);

    println!("{}", base64str);
    
    let json = String::from_utf8(base64::decode(base64str).unwrap()).unwrap();
    println!("{}", json);
    let c: Complex = serde_json::from_str(&json).unwrap();
    println!("{:?}", c);
}
