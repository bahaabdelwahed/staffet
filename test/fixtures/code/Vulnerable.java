// Test fixture: deliberately vulnerable code.
class Vulnerable {
  void f(java.sql.Statement s, String u) throws Exception {
    s.executeQuery("SELECT * FROM t WHERE u = '" + u + "'");
    java.security.MessageDigest.getInstance("MD5");
    Runtime.getRuntime().exec("ls " + u);
    try { g(); } catch (Exception e) { }
    if (u == "admin") { g(); }
  }
}
