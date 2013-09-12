import java.math.BigInteger;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;

/** Custom extension of the BouncyCastle's default org.bouncycastle.crypto.agreement.srp.SRP6Server 
 * M1, M2, Key calculation methods added.
 * @author Daniele Grasso
 */
public class SRP6ServerCustom extends SRP6Server {
	protected BigInteger M1;
	protected BigInteger M2;
	protected BigInteger Key;
	
	public SRP6ServerCustom(){
		super();
	}
	
	/** 
	 * Authenticates the received client evidence message M1 and saves it only if correct.
	 * To be called after calculating the secret S.
	 * @param M1: the client side generated evidence message
	 * @return A boolean indicating if the client message M1 was the expected one.
	 * @throws CryptoException 
	 */
	public boolean verifyClientEvidenceMessage(BigInteger clientM1) throws CryptoException{
		//verify pre-requirements
		if ((this.A==null)||(this.B==null)||(this.S==null)){
			throw new CryptoException("Impossible to compute and verify M1: some data are missing from the previous operations (A,B,S)");
		}
		// Compute the own client evidence message 'M1'
		BigInteger computedM1 = SRP6UtilCustom.calculateM1(digest, A, B, S);
		if (computedM1.equals(clientM1)){
			this.M1 = clientM1;
			return true;
		}
		return false;
	}
	
	/**
	 * Computes the server evidence message M2 using the previously verified values.
	 * To be called after successfully verifying the client evidence message M1.
	 * @return M2: the server side generated evidence message
	 * @throws CryptoException
	 */
	public BigInteger calculateServerEvidenceMessage() throws CryptoException{
		//verify pre-requirements
		if ((this.A==null)||(this.M1==null)||(this.S==null)){
			throw new CryptoException("Impossible to compute M2: some data are missing from the previous operations (A,M1,S)");
		}
		// Compute the server evidence message 'M2'
		this.M2 = SRP6UtilCustom.calculateM2(digest, A, M1, S);  
		return M2;
	}
	
	/**
	 * Computes the final session key as a result of the SRP successful mutual authentication
	 * To be called after calculating the server evidence message M2.
	 * @return Key: the mutual authenticated symmetric session key
	 * @throws CryptoException
	 */
	public BigInteger calculateSessionKey() throws CryptoException{
		//verify pre-requirements
		if ((this.S==null)||(this.M1==null)||(this.M2==null)){
			throw new CryptoException("Impossible to compute Key: some data are missing from the previous operations (S,M1,M2)");
		}
		this.Key = SRP6UtilCustom.calculateKey(digest,S);
		return Key;
	}
}
