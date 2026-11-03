//! The `executor` feature allows the execution of asynchronous operations

extern crate rimu_ws;

#[rimu_ws::main]
async fn main() {
  println!("With great power comes great electricity bills");
}

#[rimu_ws::test]
async fn test_with_runtime(runtime: &rimu_ws::executor::StdRuntime) {
  runtime
    .spawn(async move {
      println!("Behind every successful diet is an unwatched pizza");
    })
    .unwrap();
}
