//! `#[pkg::aux]` accepts bounds

rimu_ws::create_packages_aux_wrapper!();

type Api = ();

/// Generic API
pub trait GenericApi {}

impl GenericApi for &mut Api {}
impl GenericApi for Api {}
impl GenericApi for Box<Api> {}

#[rimu_ws::pkg(data_format(json), id(super::Api), transport(http))]
mod pkg {
  #[pkg::aux]
  impl<A> super::PkgsAux<A, (), ()>
  where
    A: super::GenericApi
  {}

  #[pkg::req_data]
  pub(crate) type FooReq<'any> = &'any ();

  #[pkg::res_data]
  pub(crate) type FooRes = ();
}

fn main() {
}
