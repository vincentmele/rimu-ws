macro_rules! send_go_away_method {
  () => {
    /// Sends a GOAWAY frame to the peer: no new stream opens, and the connection closes once the
    /// open streams end.
    #[inline]
    pub async fn send_go_away(&self, error_code: crate::http2::Http2ErrorCode) {
      self.shared.state.lock().conn.go_away(error_code);
      let _rslt = self.shared.flush().await;
    }
  };
}
