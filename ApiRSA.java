/*******************************************************************************************
 * La classe ApiRSA définit toutes les API pour signer un texte claire (chaîne de caractère) 
 * avec une paire de clés RSA (PK, SK) de 1024 bits et SHA256
 * @author Didier Samfat
 * @version 2.0
 * Date: 27/03/2021
 *******************************************************************************************/


package mySignature;

import java.nio.charset.Charset;
import java.security.*;
import java.util.Base64;


public class ApiRSA {
	
	private final static Charset UTF8 = Charset.forName("UTF-8"); // encodage caractère
	
	/**
	 * Génére une paire de clés (PK, SK) de 1024 bits pour l'algorithme RSA
	 * son appel dans une autre classe se fait par ApiRSA.generateKeyPair()
	 * @return : la paire de clé publique et privé
	 * @throws Exception: si tamtam
	 */
	
	public static KeyPair generateKeyPair() throws Exception {
	    
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
	    
		generator.initialize(1024, new SecureRandom());
	    
		KeyPair rsaKey = generator.generateKeyPair(); // la pair de clé (PK, SK) est généree

	    return rsaKey;
	}
	
	/**
	 * Cette méthode effectue un hash sur une chaine et la signe avec une clé privée SK
	 * son appel dans une autre classe se fait par ApiRSA.sign(..)
	 * @param texteClair : le texte à signer
	 * @param priveSK  : la clé privée SK qui doit au préalable être généré
	 * @return : retourne la signature sous forme de chaine
	 * @throws Exception: si tamtam
	 */
	
	public static String sign(String texteClair, PrivateKey priveSK) throws Exception {
		
		// utilise le hash SHA256 et signe en même temps
	    Signature privateSignature = Signature.getInstance("SHA256withRSA");
	    
	    privateSignature.initSign(priveSK); // initialise la clé privée SK
	    
	    privateSignature.update(texteClair.getBytes(UTF8));

	    byte[] signature = privateSignature.sign(); // récupère la signature sous forme d'octets

	    return Base64.getEncoder().encodeToString(signature); //retourne la signature au format chaine
	}
	
	
	/**
	 * Cette méthode vérifie qu'un text clair n'a pas été modifié après avoir été signé
	 * son appel dans une autre classe se fait par ApiRSA.verify(..)
	 * @param texteClair: le texte à vérifier
	 * @param signature : la signature du tecte calculé précédemment
	 * @param publicPK  : la clé publique PK de l'auteur
	 * @return			: retourn vrai si c'est bon
	 * @throws Exception: si tamtam
	 */
		
	public static boolean verify(String texteClair, String signature, PublicKey publicPK) throws Exception {
		
	    Signature publicSignature = Signature.getInstance("SHA256withRSA"); // re-hash le text clair
	    
	    publicSignature.initVerify(publicPK);
	    
	    publicSignature.update(texteClair.getBytes(UTF8)); // re-signe pour obtenir la signature candidate

	    byte[] signatureOctets = Base64.getDecoder().decode(signature); //encode en octet la signature candidate

	    return publicSignature.verify(signatureOctets);  // vérifie les 2 signatures et retourne vrai si ok
	}
	
}
