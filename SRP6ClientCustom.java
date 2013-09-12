import java.math.BigInteger;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;

/** Custom extension of the BouncyCastle's default org.bouncycastle.crypto.agreement.srp.SRP6Client
 * M1, M2, Key calculation methods added.
 * @author Daniele Grasso
 */
public class SRP6ClientCustom extends SRP6Client {
	protected BigInteger M1;
	protected BigInteger M2;
	protected BigInteger Key;
	public SRP6ClientCustom(){
		super();
	}
	
	/**
	 * Computes the client evidence message M1 using the previously received values.
	 * To be called after calculating the secret S.
	 * @return M1: the client side generated evidence message
	 * @throws CryptoException
	 */
	public BigInteger calculateClientEvidenceMessage() throws CryptoException{
		// verify pre-requirements
		if ((this.A==null)||(this.B==null)||(this.S==null)){
			throw new CryptoException("Impossible to compute M1: some data are missing from the previous operations (A,B,S)");
		}
		// compute the client evidence message 'M1'
		this.M1 = SRP6UtilCustom.calculateM1(digest, A, M1, S);  
		return M1;
	}
	
	/** Authenticates the server evidence message M2 received and saves it only if correct.
	 * @param M2: the server side generated evidence message
	 * @return A boolean indicating if the server message M2 was the expected one.
	 * @throws CryptoException
	 */
	public boolean verifyServerEvidenceMessage(BigInteger serverM2) throws CryptoException{
		//verify pre-requirements
		if ((this.A==null)||(this.M1==null)||(this.S==null)){
			throw new CryptoException("Impossible to compute and verify M2: some data are missing from the previous operations (A,M1,S)");
		}
		// Compute the own server evidence message 'M2'
		BigInteger computedM2 = SRP6UtilCustom.calculateM2(digest, A, M1, S);
		if (computedM2.equals(serverM2)){
			this.M2 = serverM2;
			return true;
		}
		return false;
	}
	
	/**
	 * Computes the final session key as a result of the SRP successful mutual authentication
	 * To be called after verifying the server evidence message M2.
	 * @return Key: the mutually authenticated symmetric session key
	 * @throws CryptoException
	 */
	public BigInteger calculateSessionKey() throws CryptoException{
		//verify pre-requirements (here we enforce a previous calculation of M1 and M2)
		if ((this.S==null)||(this.M1==null)||(this.M2==null)){
			throw new CryptoException("Impossible to compute Key: some data are missing from the previous operations (S,M1,M2)");
		}
		this.Key = SRP6UtilCustom.calculateKey(digest,S);
		return Key;
	}
}
