import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.concurrent.ConcurrentHashMap;

public class AtmServiceHandler implements Runnable{

    private Socket atmClientSocket;
    private ObjectInputStream inp;
    private ObjectOutputStream out;
    private KeyPair bank_keys;
    private ConcurrentHashMap<String, Account> clients;
    private SecretKey generatedSymmetricKey;
    private static SecureRandom rand = new SecureRandom();
    private static int sequenceNumber;

    public AtmServiceHandler(Socket atmClientSocket, ConcurrentHashMap<String, Account> clients, KeyPair keypair) throws Exception {
        this.atmClientSocket = atmClientSocket;
        this.inp = new ObjectInputStream(atmClientSocket.getInputStream());
        this.out = new ObjectOutputStream(atmClientSocket.getOutputStream());

        this.bank_keys = keypair;
        this.clients = clients;
        this.generatedSymmetricKey = getSymmetricKey(inp, out);
        sequenceNumber = rand.nextInt() + 1;
    }

    @Override
    public void run() {

        try {
            receiveData();
            sendData("HelloThere");  //sent rand
            sequenceNumber += 1;
            String action = receiveData();
            String received;

            switch (action) {
                case "n" -> {
                    sendData("confirm");
                    sequenceNumber += 1;
                    received = receiveData();
                    String[] params = received.split("#");
                    Account acc = clients.get(params[0]);
                    if (Double.parseDouble(params[1]) >= 10 && acc == null) {
                        Account new_acc = new Account(params[0], params[1], params[2]);
                        clients.put(params[0], new_acc);
                        System.out.println("{\"account\":\"" + params[0] + "\",\"initial_balance\":" + params[1] + "\"}");
                        sendData("{\"account\":\"" + params[0] + "\",\"initial_balance\":" + params[1] + "\"}");
                    } else {
                        sendData("no_confirm");
                    }
                }
                case "d" -> {
                    sendData("confirm");
                    sequenceNumber += 1;
                    received = receiveData();
                    String[] params = received.split("#");
                    Account c = clients.get(params[0]);
                    if (c.getPin() != Integer.parseInt(params[2])) {
                        sendData("no_confirm");
                    }
                    c.setBalance(c.getBalance() + Double.parseDouble(params[1]));
                    System.out.println("{\"account\":\"" + params[0] + "\",\"deposit\":" + Double.parseDouble(params[1]) + "\"}");
                    sendData("{\"account\":\"" + params[0] + "\",\"deposit\":" + Double.parseDouble(params[1]) + "\"}");

                }
                case "w" -> {
                    sendData("confirm");
                    sequenceNumber += 1;
                    received = receiveData();
                    String[] params = received.split("#");
                    Account c = clients.get(params[0]);
                    if (c.getPin() != Integer.parseInt(params[2])) {
                        sendData("no_confirm");
                    }
                    double res = c.getBalance() - Double.parseDouble(params[1]);
                    if (res > 0) {
                        c.setBalance(res);
                        System.out.println("{\"account\":\"" + params[0] + "\",\"withdraw\":" + Double.parseDouble(params[1]) + "\"}");
                        sendData("{\"account\":\"" + params[0] + "\",\"withdraw\":" + Double.parseDouble(params[1]) + "\"}");
                    } else {
                        sendData("no_confirm");
                    }
                }
                case "g" -> {
                    sendData("confirm");
                    sequenceNumber += 1;
                    received = receiveData();
                    String[] params = received.split("#");
                    Account c = clients.get(params[0]);
                    if (c.getPin() != Integer.parseInt(params[2])) {
                        sendData("no_confirm");
                    } else {
                        System.out.println("{\"account\":\"" + params[0] + "\",\"balance\":" + c.getBalance() + "\"}");
                        sendData("{\"account\":\"" + params[0] + "\",\"balance\":" + c.getBalance() + "\"}");
                    }
                }
            }
        } catch (Exception ex) {
            System.exit(255);
        }
    }

    public static SecretKey getSymmetricKey(ObjectInputStream inp, ObjectOutputStream out) throws Exception {
        PublicKey atmPubKey = (PublicKey)inp.readObject();

        DHParameterSpec dhParamFromAtmPubKey = ((DHPublicKey) atmPubKey).getParams();
        KeyPairGenerator bankKpairGen = KeyPairGenerator.getInstance("DH");
        bankKpairGen.initialize(dhParamFromAtmPubKey);
        KeyPair bankKpair = bankKpairGen.generateKeyPair();

        KeyAgreement bankKeyAgree = KeyAgreement.getInstance("DH");
        bankKeyAgree.init(bankKpair.getPrivate());

        out.writeObject(bankKpair.getPublic());

        bankKeyAgree.doPhase(atmPubKey, true);

        byte[] symmetricKey = bankKeyAgree.generateSecret();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(symmetricKey);

        return new SecretKeySpec(hash,"AES");
    }

    public static String obtainMACSHA256(Key symmetricKey, byte [] commands) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(symmetricKey.getEncoded(), "HmacSHA256"));
        mac.update(commands);
        return new String(mac.doFinal(), StandardCharsets.UTF_8);
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

    public void sendData(String commands) throws Exception {
        commands = sequenceNumber + ";" + commands;
        byte[] dataToSendEncrypted = encrypt(commands.getBytes(StandardCharsets.UTF_8), generatedSymmetricKey);
        dataToSendEncrypted = encrypt(dataToSendEncrypted, bank_keys.getPrivate());
        String hashedEncryptedData = obtainMACSHA256(generatedSymmetricKey, dataToSendEncrypted);
        out.writeObject(hashedEncryptedData);
        out.writeObject(dataToSendEncrypted);
        out.flush();
    }

    public String receiveData() throws Exception {
        String hashed = (String) inp.readObject();
        byte[] notHash = (byte[]) inp.readObject();
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(generatedSymmetricKey.getEncoded(), "HmacSHA256"));
        mac.update(notHash);
        String integrity_check = new String(mac.doFinal(), StandardCharsets.UTF_8);
        if (!integrity_check.equals(hashed)) {
            System.exit(255);
        }
        byte[] recovered = decrypt(notHash, bank_keys.getPrivate());
        recovered = decrypt(recovered, generatedSymmetricKey);
        String[] msg = new String(recovered, StandardCharsets.UTF_8).split(";");
        if (Integer.parseInt(msg[0]) == 0) {
            return msg[1];
        } else if (Integer.parseInt(msg[0]) != sequenceNumber) {
            System.exit(255);
        }
        return msg[1];
    }
}
