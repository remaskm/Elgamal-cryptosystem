import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.security.SecureRandom;
import java.util.Scanner;

/*
Alice is the sender.
She connects to Bob over a TCP socket
receives his public key package (p, alpha, beta)
then encrypts her message one character at a time
and sends each ciphertext pair (kE, y) to Bob.
*/

/*
Overview

Bob publishes:  p (prime), alpha (generator of Z*p), beta = alpha^d mod p
Alice does per character x:
    1. Pick a fresh random ephemeral key i  (never reused, never sent directly)
    2. kE  = alpha^i  mod p        (sent to Bob so he can rebuild kM)
    3. kM  = beta^i   mod p        (shared masking key, never transmitted)
    4. y   = x * kM   mod p        (ciphertext)
    5. Send (kE, y) to Bob
*/

public class Alice {

    static final String HOST = "localhost";
    static final int    PORT = 9090;

    public static void main(String[] args) {

        showBanner();

        // read the plaintext from the user
        Scanner sc = new Scanner(System.in);
        System.out.print("  Enter message to encrypt: ");
        String msg = sc.nextLine();

        // The message will be encrypted character by character
        System.out.println();
        System.out.println("  Message : \"" + msg + "\"");
        System.out.println("  Length  : " + msg.length() + " character(s)");
        System.out.print("  ASCII   : [");
        // each character's ASCII value is treated as an integer element of the group Z*p
        for (int i = 0; i < msg.length(); i++) {
            if (i > 0) System.out.print(", ");
            System.out.print((int) msg.charAt(i));
        }
        System.out.println("]");

        // connect to Bob. He must already be running and listening on PORT
        sep("STEP 1 - Connect to Bob");
        System.out.println("  Host: " + HOST + "   Port: " + PORT);

        try (Socket sock = new Socket(HOST, PORT)) {

            System.out.println("  Connected.");

            BufferedReader fromBob = new BufferedReader(
                    new InputStreamReader(sock.getInputStream()));
            PrintWriter toBob = new PrintWriter(
                    new OutputStreamWriter(sock.getOutputStream()), true);

            // receive Bob's public key package (p, alpha, beta)
            sep("STEP 2 - Receive Bob's Public Key (p, alpha, beta)");

            //everything here is public so an attacker watching the wire sees all three.
            //but recovering d from (alpha, beta, p) is infeasible for large p
            BigInteger p     = new BigInteger(fromBob.readLine().trim()); //p is a large prime; the group we work in is Z*p = {1,...,p-1}
            BigInteger alpha = new BigInteger(fromBob.readLine().trim()); //alpha is a primitive root (generator) of Z*p
            BigInteger beta  = new BigInteger(fromBob.readLine().trim()); //beta is alpha^d mod p, where d is Bob's private key.

            System.out.println("  p     = " + p);
            System.out.println("  alpha = " + alpha);
            System.out.println("  beta  = " + beta);
            System.out.println();
            System.out.println("  beta = alpha^d mod p, where d is Bob's secret.");
            System.out.println("  Alice knows alpha, beta, p but NOT d.");
            System.out.println("  Finding d from these values is the Discrete Log Problem.");

            // validate every character fits in Zp* = {1, ..., p-1}
            sep("STEP 3 - Check Message Fits in Zp*");
            System.out.println("  Zp* = {1, 2, ..., " + p.subtract(BigInteger.ONE) + "}");
            System.out.println("  Each character's ASCII value must be in that range.");
            System.out.println();

            int pMax = p.subtract(BigInteger.ONE).intValue(); //the default p = 257 (the smallest prime above 255) since all standard ASCII values (1–255)
            boolean ok = true;
            for (int i = 0; i < msg.length(); i++) {
                int asc = (int) msg.charAt(i);
                boolean inRange = asc >= 1 && asc <= pMax;
                System.out.println("  '" + msg.charAt(i) + "'  ASCII=" + asc
                        + "  in Zp*: " + (inRange ? "yes" : "NO - out of range!"));
                if (!inRange) ok = false;
            }

            if (!ok) {
                System.out.println();
                System.out.println("  ERROR: some characters are outside Zp*. Cannot encrypt.");
                System.out.println("  All ASCII values must be between 1 and " + pMax + ".");
                return;
            }
            System.out.println();
            System.out.println("  All characters fit in Zp*. Good to go.");

            // tell Bob how many characters are coming so he knows how many (kE, y) pairs to read from the socket.
            toBob.println(msg.length());

            /*
            encrypt and send each character to Bob
            (a) Pick i    (ephemeral key)
            (b) kE = alpha^i mod p (Alice's ephemeral public key)
            (c) kM = beta^i  mod p (shared masking key)
            (d) y  = x * kM  mod p (ciphertext)
            (e) Send (kE, y) to Bob
            */
            sep("STEP 4 - Encrypt Each Character and Send to Bob");
            System.out.println("  Processing " + msg.length() + " character(s)...");

            for (int idx = 0; idx < msg.length(); idx++) {

                char ch = msg.charAt(idx);
                // The plaintext element x is just the character's ASCII value,
                // treated as an integer in the group Z*p
                BigInteger x = BigInteger.valueOf((int) ch);

                System.out.println();
                System.out.println("  --------------------------------------------------");
                System.out.println("  Character " + (idx + 1) + " / " + msg.length()
                        + "   '" + ch + "'   x = " + x + " (ASCII)");
                System.out.println("  --------------------------------------------------");

                /*
                [A] Pick ephemeral key i — one-time use, discarded after this character.
                If Alice reuses i for two messages x1 and x2, then both ciphertexts share the same masking key kM = beta^i
                An attacker who knows or guesses x1 can compute kM = y1 * x1^(-1) mod p and then recover every other message encrypted with that i
                ElGamal is probabilistic: encrypting the same character twice gives completely different (kE, y) pairs, because kM = beta^i changes with each random i.
                */
                System.out.println();
                System.out.println("  [A] Pick ephemeral key i (one-time, thrown away after)");
                BigInteger i = randomInRange( // i is Alice's temporary private key for this single encryption.
                        new BigInteger("2"),
                        p.subtract(new BigInteger("2")));
                System.out.println("      i = " + i + "   binary: (" + i.toString(2) + ")_2");
                System.out.println("      i is Alice's temporary secret, NOT sent to Bob.");

                /*
                [B] Compute kE = alpha^i mod p  (Alice's ephemeral public key)
                kE is sent to Bob so he can independently compute the masking key kM
                */
                System.out.println();
                System.out.println("  [B] Compute kE = alpha^i mod p");
                System.out.println("      kE = " + alpha + "^" + i + " mod " + p);
                BigInteger kE = squareMultiply(alpha, i, p, "kE");
                System.out.println();
                System.out.println("      kE = " + kE + "   will be sent to Bob");


                /*
                [C] Compute masking key kM = beta^i mod p  (shared secret)
                Alice: kM = beta^i = (alpha^d)^i = alpha^(d*i) mod p
                Bob:   kM = kE^d   = (alpha^i)^d = alpha^(i*d) mod p
                both sides get the same kM without either one ever transmitting i or d directly because exponent multiplication commutes
                */
                System.out.println();
                System.out.println("  [C] Compute masking key kM = beta^i mod p");
                System.out.println("      kM = " + beta + "^" + i + " mod " + p);
                System.out.println("      (beta = alpha^d, so this = alpha^(d*i) mod p)");
                System.out.println("      (Bob will get the same kM via kE^d = alpha^(i*d) mod p)");
                BigInteger kM = squareMultiply(beta, i, p, "kM");
                System.out.println();
                System.out.println("      kM = " + kM + "   shared secret, never transmitted");

                /*
                [D] Encrypt: y = x * kM mod p
                kM acts as a multiplicative mask on x in the group Z*p.
                Every non-zero x maps to a unique y for a given kM, because Z*p is closed under multiplication and every element has an inverse.
                The inverse (kM^(-1)) is what Bob uses on his side to peel the mask off.
                If kM is uniformly random in Z*p (which it is, because i is random),then y is uniformly distributed over Z*p regardless of x
                So y reveals no information about the plaintext to a passive eavesdropper.
                 */
                System.out.println();
                System.out.println("  [D] Encrypt:  y = x * kM mod p");
                System.out.println("      y = " + x + " * " + kM + " mod " + p);
                BigInteger y = x.multiply(kM).mod(p);
                System.out.println("      y = " + x.multiply(kM) + " mod " + p + " = " + y);

                // send ciphertext pair (kE, y) to Bob
                toBob.println(kE.toString());
                toBob.println(y.toString());

                System.out.println();
                System.out.println("  [E] Sent to Bob:");
                System.out.println("      kE = " + kE); //kE lets Bob rebuild kM
                System.out.println("      y  = " + y); //y is the masked plaintext
                System.out.println("      Attacker sees kE=" + kE + " and y=" + y
                        + " but cannot find x=" + x + " without knowing d or i.");
            }

            sep("DONE - Encryption Complete");
            System.out.println("  Sent \"" + msg + "\" (" + msg.length() + " chars)");
            System.out.println("  Bob will decrypt using his private key d.");
            System.out.println();
            System.out.println("  ElGamal note: encrypting the same message again with the");
            System.out.println("  same public key produces completely different ciphertext,");
            System.out.println("  because each run picks a new random i. That is the");
            System.out.println("  probabilistic property of ElGamal.");

        } catch (ConnectException ex) {
            System.out.println();
            System.out.println("  ERROR: could not connect to Bob on port " + PORT + ".");
            System.out.println("  Start Bob.java first, then run Alice.");
        } catch (IOException ex) {
            System.err.println("Network error: " + ex.getMessage());
        }
    }

    //Computes base^exp mod m using the Square-and-Multiply algorithm.
    static BigInteger squareMultiply(BigInteger base, BigInteger exp,
                                     BigInteger mod, String name) {

        System.out.println("  Square-and-Multiply for " + name + ":");
        System.out.println("    base=" + base + "  exp=" + exp + "=(" + exp.toString(2) + ")_2  mod=" + mod);
        System.out.println("    scanning exp bits MSB first (leading 1 initialises y = base):");
        System.out.printf("    %-5s  %-4s  %-6s  %-18s%n", "bit#", "val", "op", "result"); //Write exp in binary. Scan its bits left to right (MSB to LSB).
        System.out.println("    " + "-".repeat(52));
        // Edge case: anything^0 = 1 by definition.
        if (exp.equals(BigInteger.ZERO)) {
            System.out.println("    exp=0, result=1");
            return BigInteger.ONE;
        }

        int t = exp.bitLength() - 1;          // index of the leading 1 bit

        //step 1: leading bit is always 1, so we initialize y = base and skip the first operation.
        BigInteger res = base.mod(mod);
        System.out.printf("    %-5d  %-4d  %-6s  %-18s  << init y = base%n", t, 1, "-", res);

        // Steps 2-5: process remaining bits from t-1 down to 0
        for (int i = t - 1; i >= 0; i--) {
            // Always square first — this doubles the exponent accumulated so far.
            //y = y^2 mod m
            res = res.multiply(res).mod(mod);

            int b = exp.testBit(i) ? 1 : 0;
            if (b == 1) {
                //If the bit is 1, also multiply:  y = y * base mod m
                res = res.multiply(base).mod(mod);
                System.out.printf("    %-5d  %-4d  %-6s  %-18s%n", i, b, "SQ,MUL", res);
            } else {
                //If the bit is 0, just the square is enough.
                System.out.printf("    %-5d  %-4d  %-6s  %-18s%n", i, b, "SQ", res);
            }
        }

        System.out.println("    " + "-".repeat(52));
        System.out.println("    " + name + " = " + res);
        return res;
    }

    // returns a random BigInteger r where low <= r <= high
    static BigInteger randomInRange(BigInteger low, BigInteger high) {
        SecureRandom rng = new SecureRandom(); //use SecureRandom not regular Random to avoid predictable i values,
        BigInteger range = high.subtract(low).add(BigInteger.ONE);
        BigInteger pick;
        do {
            pick = new BigInteger(range.bitLength(), rng);
        } while (pick.compareTo(range) >= 0);
        return low.add(pick);
    }

    static void showBanner() {
        System.out.println();
        System.out.println("  ElGamal Encryption - ALICE (Sender)");
        System.out.println();
    }

    static void sep(String label) {
        System.out.println();
        System.out.println("  >>> " + label);
        System.out.println();
    }
}