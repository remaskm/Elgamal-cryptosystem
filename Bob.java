import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.security.SecureRandom;
import java.util.Scanner;

/*
Bob is the receiver.
He generates the system parameters and his key pair,
opens a TCP socket and waits for Alice to connect,
sends her his public key package (p, alpha, beta),
then receives and decrypts each ciphertext pair (kE, y) she sends.
*/

/*
Overview

Setup (done once by Bob):
    1. Choose prime p and primitive root alpha of Z*p
    2. Pick private key d at random from {2, ..., p-2}
    3. Compute public key beta = alpha^d mod p
    4. Send (p, alpha, beta) to Alice

Decryption (per character received from Alice):
    Given ciphertext pair (kE, y):
    1. Rebuild masking key: kM = kE^d mod p
    2. Invert kM using Fermat's Little Theorem: kM^(-1) = kM^(p-2) mod p
    3. Recover plaintext:  x = y * kM^(-1) mod p
*/

public class Bob {

    // both sides agree on this port previously
    static final int PORT = 9090;

    public static void main(String[] args) {

        showBanner();

        // Defaults:
        // p = 257 is the smallest prime above 255, so every ASCII character (1-255)
        // is a valid element of the group Z*p = {1, 2, ..., 256}
        // alpha = 3 is a primitive root mod 257, meaning 3^1, 3^2, ..., 3^256
        // hit every element of Z*257 exactly once

        BigInteger defaultP     = new BigInteger("257");
        BigInteger defaultAlpha = new BigInteger("3");

        Scanner sc = new Scanner(System.in);

        System.out.println("  Default parameters:  p = " + defaultP + ",  alpha = " + defaultAlpha);
        System.out.print("  Press Enter to use defaults, or type 'custom' to supply your own: ");
        String choice = sc.nextLine().trim();

        BigInteger p;
        BigInteger alpha;

        if (choice.equalsIgnoreCase("custom")) {
            System.out.print("  Enter p (prime modulus): ");
            p = new BigInteger(sc.nextLine().trim());
            System.out.print("  Enter alpha (primitive root mod p): ");
            alpha = new BigInteger(sc.nextLine().trim());

            //Primality Check
            // ElGamal requires p to be prime so that Z*p forms a proper cyclic group.
            // If p is not prime the group structure breaks and decryption will produce garbage.
            // isProbablePrime(30) runs Miller-Rabin with 30 rounds — false-positive chance is ~10^-18
            if (!p.isProbablePrime(30)) {
                System.out.println("\n      WARNING: The entered p does NOT appear to be a prime number!");
                System.out.println("     ElGamal encryption requires a prime modulus.");
                System.out.println("     Decryption will likely fail or produce wrong results.");
                System.out.print("     Do you still want to continue? (Y/N): ");
                String cont = sc.nextLine().trim().toUpperCase();
                if (!cont.startsWith("Y")) {
                    System.out.println("Exiting...");
                    System.exit(0);
                }
            }
        } else {
            p = defaultP;
            alpha = defaultAlpha;
        }

        sep("STEP 1 - System Parameters");
        // Z*p = {1, 2, ..., p-1} under multiplication mod p is a finite cyclic group of order p-1
        // alpha generates every element in that group via alpha^1, alpha^2, ..., alpha^(p-1)
        System.out.println("  p     = " + p  + "   (prime modulus)");
        System.out.println("  alpha = " + alpha + "   (primitive root / generator of Zp*)");
        System.out.println("  group = Zp* = {1, 2, ..., " + p.subtract(BigInteger.ONE) + "}");
        System.out.println("  |Zp*| = " + p.subtract(BigInteger.ONE));

        // The valid range is {2, ..., p-2}
        //   d = 1   -> beta = alpha, which immediately reveals d
        //   d = p-1 -> beta = alpha^(p-1) = 1 mod p (Fermat), so kM = 1 and y = x — no encryption
        // d is NEVER transmitted. Recovering it from beta = alpha^d mod p is the DLP.
        sep("STEP 2 - Private Key");
        BigInteger d = randomInRange(new BigInteger("2"), p.subtract(new BigInteger("2")));
        System.out.println("  Picked d randomly from {2, ..., " + p.subtract(new BigInteger("2")) + "}");
        System.out.println("  d = " + d + "   binary: (" + d.toString(2) + ")_2");
        System.out.println("  d stays secret on Bob's side, never transmitted.");

        // compute public key beta = alpha^d mod p
        // Anyone can compute alpha^d given d, but going backwards
        // (finding d from alpha^d) is the DLP .. hard for large p.

        sep("STEP 3 - Public Key  beta = alpha^d mod p");
        System.out.println("  beta = " + alpha + "^" + d + " mod " + p);
        System.out.println();

        BigInteger beta = squareMultiply(alpha, d, p, "beta");

        System.out.println();
        System.out.println("  Bob's key pair:");
        System.out.println("    public  beta = " + beta);
        System.out.println("    private d    = " + d + "  (secret)");

        //open server socket and wait for Alice
        sep("STEP 4 - Network: waiting for Alice on port " + PORT);
        System.out.println("  Listening... (start Alice.java in another terminal)");

        try (ServerSocket ss = new ServerSocket(PORT)) {

            Socket conn = ss.accept();
            System.out.println("  Alice connected from " + conn.getInetAddress().getHostAddress());

            BufferedReader fromAlice = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()));
            PrintWriter toAlice = new PrintWriter(
                    new OutputStreamWriter(conn.getOutputStream()), true);

            // send public key package (p, alpha, beta) to Alice
            // Alice needs all three values to encrypt.
            // Everything here is public even an attacker can see it too.

            sep("STEP 5 - Sending Public Key Package to Alice");
            toAlice.println(p.toString());
            toAlice.println(alpha.toString());
            toAlice.println(beta.toString());

            System.out.println("  Sent: p = " + p);
            System.out.println("  Sent: alpha = " + alpha);
            System.out.println("  Sent: beta  = " + beta);
            System.out.println();
            System.out.println("  A passive attacker watching this exchange sees p, alpha, beta.");
            System.out.println("  To recover d they need to solve " + alpha + "^d = " + beta + " mod " + p);
            System.out.println("  That is the Discrete Log Problem - hard for large p.");

            // read how many characters Alice will send so we know how many (kE, y) pairs to expect
            int total = Integer.parseInt(fromAlice.readLine().trim());

            /*
            Receive and decrypt each character from Alice.
            Each character arrives as a pair (kE, y) where:
                kE = alpha^i mod p  — Alice's ephemeral public key for this character
                y  = x * kM mod p  — the masked plaintext

            Decryption steps:
            [A] kM = kE^d mod p            (rebuild the shared masking key)
            [B] kM^(-1) = kM^(p-2) mod p  (invert kM using Fermat's Little Theorem)
            [C] x = y * kM^(-1) mod p      (unmask to recover plaintext)
            */
            sep("STEP 6 - Receiving and Decrypting " + total + " character(s) from Alice");
            System.out.println("  Each character comes as a pair (kE, y).");
            System.out.println();

            StringBuilder result = new StringBuilder();

            for (int idx = 0; idx < total; idx++) {

                BigInteger kE = new BigInteger(fromAlice.readLine().trim());
                BigInteger y  = new BigInteger(fromAlice.readLine().trim());

                System.out.println("  --------------------------------------------------");
                System.out.println("  Character " + (idx + 1) + " / " + total);
                System.out.println("  --------------------------------------------------");
                System.out.println("  kE = " + kE + "   this is alpha^i mod p (Alice's ephemeral value)");
                System.out.println("  y  = " + y  + "   this is x * kM mod p (the masked ciphertext)");
                System.out.println();

                /*
                [A] Rebuild masking key: kM = kE^d mod p
                Alice computed: kM = beta^i = (alpha^d)^i = alpha^(d*i) mod p
                Bob computes:   kM = kE^d   = (alpha^i)^d = alpha^(i*d) mod p
                both sides get the same kM because exponents commute (d*i = i*d)
                neither party ever transmitted i or d — this is the DHKE mechanism inside ElGamal
                */
                System.out.println("  [A] Rebuild masking key:  kM = kE^d mod p");
                System.out.println("      kM = " + kE + "^" + d + " mod " + p);
                BigInteger kM = squareMultiply(kE, d, p, "kM");
                System.out.println();
                System.out.println("      kM = " + kM);

                /*
                [B] Compute inverse of kM using Fermat's Little Theorem
                For any a in Z*p and prime p: a^(p-1) = 1 mod p
                Rearranging: a * a^(p-2) = 1 mod p, so a^(-1) = a^(p-2) mod p
                This lets us compute the inverse with a single Square-and-Multiply
                instead of running the extended Euclidean algorithm
                */
                System.out.println();
                System.out.println("  [B] Compute inverse of kM using Fermat's little theorem:");
                System.out.println("      p prime => kM^(p-1) = 1 mod p");
                System.out.println("      so kM^(-1) = kM^(p-2) mod p");
                System.out.println("      kM^(-1) = " + kM + "^" + p.subtract(BigInteger.TWO) + " mod " + p);

                BigInteger invKM = squareMultiply(kM, p.subtract(BigInteger.TWO), p, "kM_inv");
                // sanity check: kM * kM^(-1) must equal 1 in Z*p
                System.out.println();
                System.out.println("      sanity check: kM * kM^(-1) mod p = "
                        + kM.multiply(invKM).mod(p) + "  (should be 1)");

                /*
                [C] Decrypt: x = y * kM^(-1) mod p
                Since y = x * kM mod p, multiplying both sides by kM^(-1) cancels the mask:
                      y * kM^(-1) = x * kM * kM^(-1) = x * 1 = x mod p
                x is then cast back to a char using its ASCII value
                */
                System.out.println();
                System.out.println("  [C] Decrypt:  x = y * kM^(-1) mod p");
                System.out.println("      x = " + y + " * " + invKM + " mod " + p);

                BigInteger x = y.multiply(invKM).mod(p);
                char ch = (char) x.intValue();
                result.append(ch);

                System.out.println("      x = " + x + "   =>   '" + ch + "' (ASCII " + x + ")");
                System.out.println();
            }

            sep("DONE - Decrypted Message");
            System.out.println("  \"" + result.toString() + "\"");
            System.out.println();

            conn.close();

        } catch (IOException ex) {
            System.err.println("Network error: " + ex.getMessage());
        }
    }

    // Computes base^exp mod m using the Square-and-Multiply algorithm.
    static BigInteger squareMultiply(BigInteger base, BigInteger exp,
                                     BigInteger mod, String name) {

        System.out.println("  Square-and-Multiply for " + name + ":");
        System.out.println("    base = " + base + "   exp = " + exp
                + " = (" + exp.toString(2) + ")_2   mod = " + mod);
        System.out.println("    processing bits from MSB to LSB (leading 1 initialises y = base):");
        System.out.printf("    %-5s  %-4s  %-6s  %-18s%n",
                "bit#", "val", "op", "result");
        System.out.println("    " + "-".repeat(52));

        // edge case: anything^0 = 1
        if (exp.equals(BigInteger.ZERO)) {
            System.out.println("    exp is 0, result = 1");
            return BigInteger.ONE;
        }

        int t = exp.bitLength() - 1;          // index of the leading 1-bit

        // leading bit is always 1, so initialize y = base and skip the first operation
        // squaring here would give base^2 instead of base^1 which throws off everything after
        BigInteger res = base.mod(mod);
        System.out.printf("    %-5d  %-4d  %-6s  %-18s  << init y = base%n", t, 1, "-", res);

        // Steps 2-5: process remaining bits from t-1 down to 0
        for (int i = t - 1; i >= 0; i--) {
            // always square — doubles the exponent built up so far
            // y = y^2 mod m
            res = res.multiply(res).mod(mod);
            int b = exp.testBit(i) ? 1 : 0;
            if (b == 1) {
                // bit is 1: also multiply by base to add 1 to the exponent
                // y = y * base mod m
                res = res.multiply(base).mod(mod);
                System.out.printf("    %-5d  %-4d  %-6s  %-18s%n", i, b, "SQ,MUL", res);
            } else {
                // bit is 0: squaring alone was enough
                System.out.printf("    %-5d  %-4d  %-6s  %-18s%n", i, b, "SQ", res);
            }
        }

        System.out.println("    " + "-".repeat(52));
        System.out.println("    " + name + " = " + res);
        return res;
    }

    // pick a random BigInteger r such that low <= r <= high
    static BigInteger randomInRange(BigInteger low, BigInteger high) {
        SecureRandom rng = new SecureRandom(); // use SecureRandom not regular Random — a predictable d would let an attacker just guess it
        BigInteger range = high.subtract(low).add(BigInteger.ONE);
        BigInteger pick;
        do {
            pick = new BigInteger(range.bitLength(), rng);
        } while (pick.compareTo(range) >= 0);
        return low.add(pick);
    }

    static void showBanner() {
        System.out.println();
        System.out.println("  ElGamal Encryption - BOB (Receiver)");
        System.out.println();
    }

    static void sep(String label) {
        System.out.println();
        System.out.println("  >>> " + label);
        System.out.println();
    }
}