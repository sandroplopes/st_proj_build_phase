import java.net.Socket;
import java.io.*;

import java.nio.charset.StandardCharsets;
import java.security.*;

import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import org.apache.commons.cli.*;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class AtmService {

    private static String BANK_IP_ADDRESS = "127.0.0.1";
    private static int BANK_SERVER_PORT = 3000;
    private static String BANK_AUTH_FILE_NAME = "bank.auth";
    private static final String dir = System.getProperty("user.dir");
    private static Socket socketToServer;
    private static ObjectOutputStream out;
    private static ObjectInputStream inp;

    private static Key generatedSymmetricKey, anti_man_in_the_middle_key;
    private static int seqNumber = 0;


    public static void main(String[] args) throws Exception {

        if (args.length == 0 || args.length == 1 || args.length > 4096)
            System.exit(255);

        Options options = cliParser();
        CommandLineParser parser = new DefaultParser(true);

        HashMap<String, String> cmd_hashmap = new HashMap<>();
        try {

            CommandLine cmdIn = parser.parse(options, args);
            Option[] parsed_Options = cmdIn.getOptions();

            for (Option opt : parsed_Options) {

                if (opt.getOpt().equals("s")) {
                    BANK_AUTH_FILE_NAME = opt.getValue().endsWith(".auth") ? opt.getValue() : opt.getValue()+".auth";
                    cmd_hashmap.put("s", BANK_AUTH_FILE_NAME);
                } else if (opt.getOpt().equals("a")) {
                    cmd_hashmap.put("a", opt.getValue());
                } else if (opt.getOpt().equals("i")) {
                    BANK_IP_ADDRESS = opt.getValue();
                    cmd_hashmap.put("i", BANK_IP_ADDRESS);
                } else if (opt.getOpt().equals("p")) {
                    BANK_SERVER_PORT = Integer.parseInt(opt.getValue());
                    cmd_hashmap.put("p", String.valueOf(BANK_SERVER_PORT));
                } else if (opt.getOpt().equals("c")) {
                    cmd_hashmap.put("c", opt.getValue());
                } else if (opt.getOpt().equals("n")) {
                    cmd_hashmap.put("n", opt.getValue());
                } else if (opt.getOpt().equals("d")) {
                    cmd_hashmap.put("d", opt.getValue());
                } else if (opt.getOpt().equals("w")) {
                    cmd_hashmap.put("w", opt.getValue());
                } else if (opt.getOpt().equals("g")) {
                    cmd_hashmap.put("g", "0");
                }
            }
        } catch (Exception e) {
            System.exit(255);
        }

        File bankAuth = new File(dir +"/src/"+BANK_AUTH_FILE_NAME);
        if(!bankAuth.exists()){
            System.exit(255);
        }
        FileInputStream fis = new FileInputStream(dir + "/src/" + BANK_AUTH_FILE_NAME);
        byte[] encodedPublicKey = new byte[(int) bankAuth.length()];
        fis.read(encodedPublicKey);
        fis.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        anti_man_in_the_middle_key = keyFactory.generatePublic(publicKeySpec);

        socketToServer = new Socket(BANK_IP_ADDRESS, BANK_SERVER_PORT);
        out = new ObjectOutputStream(socketToServer.getOutputStream());
        inp = new ObjectInputStream(socketToServer.getInputStream());
        generatedSymmetricKey = getSymmetricKey(inp, out);


        sendData("Hello", seqNumber);
        String res = receiveData();
        if (!res.equals("HelloThere"))
            System.exit(255);

        seqNumber += 1;

        if (cmd_hashmap.get("n") != null) {
            sendData("n", seqNumber);
            res = receiveData();
            if (!res.equals("confirm"))
                System.exit(255);
            seqNumber += 1;
            String name = cmd_hashmap.get("a");
            name = cmd_hashmap.get("c") != null ? cmd_hashmap.get("c") : name;
            name = name.endsWith(".card") ? name : name + ".card";
            String info = cmd_hashmap.get("a") + "#" + cmd_hashmap.get("n") + "#" + createCard(name);
            sendData(info, seqNumber);
        } else if (cmd_hashmap.get("d") != null) {
            sendData("d", seqNumber);
            res = receiveData();
            if (!res.equals("confirm"))
                System.exit(255);
            seqNumber += 1;
            String name = cmd_hashmap.get("a");
            name = cmd_hashmap.get("c") != null ? cmd_hashmap.get("c") : name;
            name = name.endsWith(".card") ? name : name + ".card";
            String info = cmd_hashmap.get("a") + "#" + cmd_hashmap.get("d") + "#" + readCardPin(name);
            sendData(info, seqNumber);
        } else if (cmd_hashmap.get("w") != null) {
            sendData("w", seqNumber);
            res = receiveData();
            if (!res.equals("confirm"))
                System.exit(255);
            seqNumber += 1;
            String name = cmd_hashmap.get("a");
            name = cmd_hashmap.get("c") != null ? cmd_hashmap.get("c") : name;
            name = name.endsWith(".card") ? name : name + ".card";
            String info = cmd_hashmap.get("a") + "#" + cmd_hashmap.get("w") + "#" + readCardPin(name);
            sendData(info, seqNumber);
        } else if (cmd_hashmap.get("g") != null) {
            sendData("g", seqNumber);
            res = receiveData();
            if (!res.equals("confirm"))
                System.exit(255);
            seqNumber += 1;
            String name = cmd_hashmap.get("a");
            name = cmd_hashmap.get("c") != null ? cmd_hashmap.get("c") : name;
            name = name.endsWith(".card") ? name : name + ".card";
            String info = cmd_hashmap.get("a") + "#" + cmd_hashmap.get("g") + "#" + readCardPin(name);
            sendData(info, seqNumber);
        }
        res = receiveData();
        if (res.equals("no_confirm"))
            System.exit(255);

        System.out.println(res);
    }

    public static Options cliParser() {
        try{
            Options options = new Options();

            Option account = new Option("a", "account", true, "the customer bank account name");
            Option authfile = new Option("s", "authfile", true, "name of the bank auth file");
            Option ip = new Option("i", "ip", true, "the IP address of bank or store");
            Option port = new Option("p", "port", true, "the port of bank or store");
            Option usrcard = new Option("c", "usrcard", true, "The customer's atm card file");

            Option new_acc = new Option("n", "newacc", true, "create a new account with the given balance");
            Option deposit = new Option("d", "deposit", true, "deposit the amount specified");
            Option withdraw = new Option("w", "withdraw", true, "Withdraw the amount of money specified");
            Option balance = new Option("g", "balance", true, "get the current balance of the account");

            account.setRequired(true);
            authfile.setRequired(false);
            ip.setRequired(false);
            port.setRequired(false);
            usrcard.setRequired(false);

            options.addOption(port);
            options.addOption(authfile);
            options.addOption(usrcard);
            options.addOption(ip);
            options.addOption(account);

            options.addOption(new_acc);
            options.addOption(deposit);
            options.addOption(withdraw);

            balance.setArgs(0);
            options.addOption(balance);

            return options;
        }catch (Exception e){
            System.exit(255);
        }
        return null;
    }

    public static SecretKey getSymmetricKey(ObjectInputStream inp, ObjectOutputStream out) throws Exception {
        KeyPairGenerator atmKpairGen = KeyPairGenerator.getInstance("DH");
        atmKpairGen.initialize(2048);
        KeyPair atmKpair = atmKpairGen.generateKeyPair();

        KeyAgreement atmKeyAgree = KeyAgreement.getInstance("DH");
        atmKeyAgree.init(atmKpair.getPrivate());

        out.writeObject(atmKpair.getPublic());

        PublicKey bobPubKey = (PublicKey)inp.readObject();

        atmKeyAgree.doPhase(bobPubKey, true);

        byte[] symmetricKey = atmKeyAgree.generateSecret();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(symmetricKey);

        return new SecretKeySpec(hash,"AES");
    }

    public static byte[] encrypt(byte[] data, Key key) {
        try {
            Cipher cipher = Cipher.getInstance(key.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println(ex.getMessage());
            return data;
        }
    }

    public static byte[] decrypt(byte[] data, Key key) {
        try {
            Cipher cipher = Cipher.getInstance(key.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println(ex.getMessage());
            return data;
        }
    }

    public static void sendData(String commands, int num_seq) throws Exception {
        commands = num_seq + ";" + commands;
        byte[] dataToSendEncrypted = encrypt(commands.getBytes(StandardCharsets.UTF_8), generatedSymmetricKey);
        dataToSendEncrypted = encrypt(dataToSendEncrypted, anti_man_in_the_middle_key);
        String hashedEncryptedData = obtainMACSHA256(generatedSymmetricKey, dataToSendEncrypted);
        out.writeObject(hashedEncryptedData);
        out.writeObject(dataToSendEncrypted);
        out.flush();
    }

    public static String receiveData() throws Exception {
        String hashed = (String) inp.readObject();
        byte[] notHash = (byte[]) inp.readObject();
        String integrity_check = obtainMACSHA256(generatedSymmetricKey, notHash);
        if (!integrity_check.equals(hashed))
            System.exit(255);
        byte[] recovered = decrypt(notHash, anti_man_in_the_middle_key);
        recovered = decrypt(recovered, generatedSymmetricKey);
        String[] msg = new String(recovered, StandardCharsets.UTF_8).split(";");
        if (seqNumber == 0)
            seqNumber = Integer.parseInt(msg[0]);
        else if (Integer.parseInt(msg[0]) != seqNumber)
            System.exit(255);
        return msg[1];
    }

    public static String obtainMACSHA256(Key symmetricKey, byte [] commands) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(symmetricKey.getEncoded(), "HmacSHA256"));
        mac.update(commands);
        return new String(mac.doFinal(), StandardCharsets.UTF_8);
    }

    private static String createCard(String cardName) throws Exception {
        File theDir = new File(dir+"/src/CardFiles/");
        if (!theDir.exists()) {
            theDir.mkdirs();
        }
        File cardFile = new File(dir +"/src/CardFiles/" +cardName);
        if (cardFile.exists()) {
            System.exit(255);
        }
        Random random = new Random();
        String pin = String.format("%04d", random.nextInt(10000));
        PrintWriter writer = new PrintWriter(dir + "/src/CardFiles/" +cardName, StandardCharsets.UTF_8);
        writer.println(pin);
        writer.close();
        return pin;
    }

    private static String readCardPin(String cardFile) throws FileNotFoundException {
        File card = new File(dir+"/src/CardFiles/"+cardFile);
        Scanner sc = new Scanner(card);
        String pin = sc.next();
        sc.close();
        return pin;
    }
}