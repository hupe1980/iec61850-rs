// IEC61850bean as an interop peer: its client against a server, or its server for a client.
// Prints one `OK|FAIL|SKIP <step>[: detail]` line per step (tests/interop/iec61850bean's
// contract with tests/interop.rs) and exits non-zero if any step failed.
//
//   java Probe client <host> <port>
//   java Probe server <port> <model.icd>
import com.beanit.iec61850bean.*;
import java.io.IOException;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.*;

public class Probe {
  static boolean failed = false;

  static void ok(String step, String detail) { System.out.println("OK " + step + (detail.isEmpty() ? "" : ": " + detail)); }
  static void fail(String step, Throwable e) {
    failed = true;
    System.out.println("FAIL " + step + ": " + e);
    for (StackTraceElement f : e.getStackTrace()) System.err.println("    at " + f);
  }
  static void skip(String step, String why) { System.out.println("SKIP " + step + ": " + why); }

  public static void main(String[] args) throws Exception {
    if (args.length >= 3 && args[0].equals("client")) client(args[1], Integer.parseInt(args[2]));
    else if (args.length >= 3 && args[0].equals("server")) server(Integer.parseInt(args[1]), args[2]);
    else { System.err.println("usage: Probe client <host> <port> | server <port> <model.icd>"); System.exit(2); }
    System.out.flush();
    System.exit(failed ? 1 : 0);
  }

  static void client(String host, int port) {
    BlockingQueue<Report> reports = new LinkedBlockingQueue<>();
    ClientAssociation a;
    try {
      a = new ClientSap().associate(InetAddress.getByName(host), port, null, new ClientEventListener() {
        public void newReport(Report r) { reports.add(r); }
        public void associationClosed(IOException e) {}
      });
      ok("associate", "");
    } catch (Exception e) { fail("associate", e); return; }

    ServerModel m;
    try {
      m = a.retrieveModel();
      ok("model", m.getChildren().size() + " logical devices");
    } catch (Exception e) { fail("model", e); a.close(); return; }

    try {
      a.getAllDataValues();
      ok("read", m.getBasicDataAttributes().size() + " attributes");
    } catch (Exception e) { fail("read", e); }

    Urcb urcb = m.getUrcbs().stream().findFirst().orElse(null);
    if (urcb == null) skip("report", "the model has no unbuffered report control block");
    else {
      try {
        a.getRcbValues(urcb);
        urcb.getTrgOps().setGeneralInterrogation(true);
        urcb.getTrgOps().setDataChange(true);
        List<ServiceError> errs = a.setRcbValues(urcb, false, false, false, false, true, false, false, false);
        if (errs.stream().anyMatch(Objects::nonNull)) throw new IOException("SetRCBValues: " + errs);
        ok("write", "TrgOps of " + urcb.getReference());
        a.enableReporting(urcb);
        a.startGi(urcb);
        Report r = reports.poll(10, TimeUnit.SECONDS);
        if (r == null) throw new IOException("no report within 10 s of a general interrogation");
        ok("report", r.getRptId() + " with " + r.getValues().size() + " values");
        a.disableReporting(urcb);
      } catch (Exception e) { fail("report", e); }
    }

    FcModelNode control = null;
    for (ModelNode ld : m.getChildren())
      for (ModelNode ln : ld.getChildren()) {
        ModelNode pos = ln.getChild("Pos", Fc.CO);
        if (control == null && pos instanceof FcModelNode) control = (FcModelNode) pos;
      }
    if (control == null) skip("control-direct", "no controllable Pos in the model");
    else {
      try {
        ModelNode ctlVal = control.getChild("Oper").getChild("ctlVal");
        if (ctlVal instanceof BdaDoubleBitPos) ((BdaDoubleBitPos) ctlVal).setDoubleBitPos(BdaDoubleBitPos.DoubleBitPos.ON);
        else if (ctlVal instanceof BdaBoolean) ((BdaBoolean) ctlVal).setValue(true);
        a.operate(control);
        ok("control-direct", control.getReference().toString());
      } catch (Exception e) { fail("control-direct", e); }
    }

    try {
      List<FileInformation> files = a.getFileDirectory("");
      ok("files", files.size() + " entries");
    } catch (ServiceError e) {
      skip("files", "the server has no file store: " + e.getMessage());
    } catch (Exception e) { fail("files", e); }

    a.close();
    ok("release", "");
  }

  static void server(int port, String model) throws Exception {
    List<ServerModel> models = SclParser.parse(model);
    ServerSap sap = new ServerSap(port, 0, null, models.get(0), null);
    sap.startListening(new ServerEventListener() {
      public List<ServiceError> write(List<BasicDataAttribute> bdas) { return null; }
      public void serverStoppedListening(ServerSap s) {}
    });
    System.out.println("READY " + port);
    System.out.flush();
    Thread.sleep(Long.MAX_VALUE);
  }
}
