#[rimu_ws::pkg]
mod a {
}

#[rimu_ws::pkg]
mod b {
  #[pkg::req_data]
  struct Req(
    i32
  );
}

#[rimu_ws::pkg]
mod c {
  #[pkg::res_data]
  struct Res;
}

fn main() {
}
