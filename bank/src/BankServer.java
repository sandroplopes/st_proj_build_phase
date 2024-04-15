import javax.crypto.Cipher;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BankServer {

    private static int BANK_SERVER_PORT = 3000;
    private static String AUTH_FILE_NAME = "bank.auth";
    public static String dir = System.getProperty("user.dir");
    private final ExecutorService threadpool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

    BankServer(int bankServerPort) {
        BANK_SERVER_PORT = bankServerPort;
    }

    public static void main(String[] args) {

        try {
            List<String> commandsList = Arrays.asList(args);

            if (commandsList.stream().noneMatch((s) -> s.startsWith("-s"))
                    && commandsList.stream().noneMatch((p) -> p.startsWith("-p"))
                    && !commandsList.isEmpty()) {
                System.exit(255);
            }

            // parse cmdline
            String correctPort = "^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$";
            for (int i = 0; i < args.length; i++) {

                if (args[i].startsWith("-p") && args[i].length() > 2) {
                    String port = args[i].substring(2);
                    if (port.matches(correctPort)
                            && Integer.parseInt(port) >= 1024
                            && Integer.parseInt(port) <= 65535) {
                        BANK_SERVER_PORT = Integer.parseInt(port);
                    }
                } else if (args[i].startsWith("-p") && args[i].length() == 2) {
                    if (args[i+1].matches(correctPort)
                            && Integer.parseInt(args[i + 1]) >= 1024
                            && Integer.parseInt(args[i + 1]) <= 65535) {
                        BANK_SERVER_PORT = Integer.parseInt(args[i + 1]);
                    }
                }

                if (args[i].startsWith("-s") && args[i].length() > 2) {
                    AUTH_FILE_NAME = args[i].substring(2);
                } else if (args[i].startsWith("-s") && args[i].length() == 2) {
                    if (i != args.length - 1) {
                        AUTH_FILE_NAME = args[i + 1];
                    }
                }
            }

            //create server and serv
            BankServer bs = new BankServer(BANK_SERVER_PORT);
            KeyPair kp = bs.writeAuthFile(AUTH_FILE_NAME);
            bs.serv(kp);

        } catch (Exception e) {
            //System.err.println(e.getMessage());
            System.out.println(255);
            System.exit(255);
        }
    }

    public void serv(KeyPair kpair) throws Exception {

        ServerSocket serverSocket = new ServerSocket(BANK_SERVER_PORT);
        System.out.println("created");

        ConcurrentHashMap<String, Account> clients = new ConcurrentHashMap<>();

        while (true) {
            Socket atmClient = serverSocket.accept();
            try {
                AtmServiceHandler atmClientHandler = new AtmServiceHandler(atmClient, clients, kpair);
                threadpool.execute(atmClientHandler);
            } catch (Exception e) {
                System.err.println(e.getMessage());
            }
        }
    }

    public KeyPair writeAuthFile(String name) throws NoSuchAlgorithmException, IOException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);

        KeyPair keypair = keyGen.generateKeyPair();
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keypair.getPublic().getEncoded());
        File filePublicKey = new File(dir + "/src/" + AUTH_FILE_NAME);
        if (filePublicKey.exists())
            System.exit(255);

        FileOutputStream fos = new FileOutputStream(dir + "/src/" + AUTH_FILE_NAME);
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        return keypair;
    }
}
