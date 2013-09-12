import java.math.BigInteger;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;

/**
 *  Custom extension of the BouncyCastle's default org.bouncycastle.crypto.agreement.srp.SRP6Util, 
 *  adding the methods for the calculation of M1, M2, and Key
 * @author Daniele Grasso
 */
public class SRP6UtilCustom extends SRP6Util {

	/**
	 * Computes the client evidence message (M1) according to the standard routine:
	 * M1 = H( A | B | S )
	 * @param digest The Digest used as the hashing function H
	 * @param A The public client value
	 * @param B The public server value
	 * @param S The secret calculated by both sides
	 * @return M1 The calculated client evidence message
	 */
	public static BigInteger calculateM1(Digest digest, BigInteger A, BigInteger B, BigInteger S) {
		byte[] _output = new byte[digest.getDigestSize()];
		byte[] _A = A.toByteArray();
		byte[] _B = B.toByteArray();
		byte[] _S = S.toByteArray();
		digest.update(_A, 0, _A.length);
		digest.update(_B, 0, _B.length);
		digest.update(_S, 0, _S.length);
		digest.doFinal(_output, 0);
		BigInteger M1 = new BigInteger(1, _output);
		return M1;
	}

	/**
	 * Computes the server evidence message (M2) according to the standard routine:
	 * M2 = H( A | M1 | S )
	 * @param digest The Digest used as the hashing function H
	 * @param A The public client value
	 * @param M1 The client evidence message
	 * @param S The secret calculated by both sides
	 * @return M2 The calculated server evidence message
	 */
	public static BigInteger calculateM2(Digest digest, BigInteger A, BigInteger M1, BigInteger S){
		byte[] _output = new byte[digest.getDigestSize()];
		byte[] _A = A.toByteArray();
		byte[] _M1 = M1.toByteArray();
		byte[] _S = S.toByteArray();
		digest.update(_A, 0, _A.length);
		digest.update(_M1,0,_M1.length);
		digest.update(_S, 0, _S.length);
		digest.doFinal(_output, 0);
		BigInteger M2 = new BigInteger(1, _output);
		return M2;
	}

	/**
	 * Computes the final Key according to the standard routine: Key = H(S)
	 * @param digest The Digest used as the hashing function H
	 * @param S The secret calculated by both sides
	 * @return
	 */
	public static BigInteger calculateKey(Digest digest, BigInteger S) {
		byte[] _output = new byte[digest.getDigestSize()];
		byte[] _S = S.toByteArray();
		digest.update(_S, 0, _S.length);
		digest.doFinal(_output, 0);
		BigInteger Key = new BigInteger(1, _output);
		return Key;
	}
}
