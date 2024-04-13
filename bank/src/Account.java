import java.io.IOException;
import java.util.UUID;

public class Account {

    private final UUID id = UUID.randomUUID();
    private final String name;
    private double balance;
    private int pin;

    public Account(String name, String balance, String pin) throws IOException {
        this.name = name;
        this.balance = Double.parseDouble(balance);
        this.pin = Integer.parseInt(pin);
    }

    public UUID getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public double getBalance() {
        return balance;
    }

    public void setBalance(double balance) {
        this.balance = balance;
    }

    public int getPin() {
        return pin;
    }

    public void setPin(int pin) {
        this.pin = pin;
    }
}
