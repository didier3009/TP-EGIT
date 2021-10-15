/********************************************************************
 * Programme: 	SignTestFile
 * Description:	Signe avec une clé privée l'enpreinte numérique 
 * d'un fichier texte ou source ex foo.java ou foo.c 
 * Auteur:		Didier Samfat
 * Date:		26 Mar 2021
 * Version:		1.0
 ********************************************************************/

package mySignature;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.*;
import java.util.*;


public class SignTextFile {
	
	public static void main(String[] args) throws Exception{
		
		int choix = 1;
		
		KeyPair maClef = ApiRSA.generateKeyPair();
		
		String signature = signFile("./HelloWorld.java", maClef.getPrivate());
		
		System.out.println("\n **** RSA SHA256 Signature **** \n");
		System.out.println(signature);
		
		Scanner saisir = new Scanner(System.in);
		while (choix != 2) {
			
			System.out.printf(" \nTaper 1 pour vérifier la signature du fichier");
			System.out.printf(" \nTaper 2 pour quitter ...\n");
			System.out.printf( "\n Votre choix >> ");
			
			choix = saisir.nextInt();
			switch(choix) {
			
			case 1 :
				
				if (verifySignedFile("./HelloWorld.java", signature, maClef.getPublic()))
					System.out.printf("\n*** Le Fichier est intègre et l'auteur vérifié ***\n");
				else
					System.out.printf("\n!!! Le Fichier est corrompu !!!\n");
								
				break;
				
			case 2 :
				System.out.printf("\n Bye et à bientôt !\n");
				break;
			
			default:
				System.out.println("Attention !: Taper 1 pour vérifier ou 2 pour quitter ...");
				
			}
		} 
		saisir.close();
	}

/**
 * Cette Méthode signe un fichier avec une clé privée SK RSA
 * @param nomFichier: Le nom du fichier
 * @param priveSK: la clé privé RSA
 * @return : la signature numérique du fichier
 * @throws Exception
 */
	
static String signFile(String nomFichier, PrivateKey priveSK) throws Exception{
		
		try {
			  			  
		      RandomAccessFile fichier = new RandomAccessFile(nomFichier, "r");
		      byte[] data = new byte[(int)fichier.length()];
		      fichier.readFully(data);
		      
		      // convertit les data en string
		      String chaine = new String(data);
		      
		      //affiche le contenu du fichier texte
		      System.out.printf("\n%s\n",chaine);
		      
		      fichier.close();
		      return ApiRSA.sign(chaine, priveSK); // retourne la signature
		    }
		    catch (FileNotFoundException e) {}
		    catch (IOException e) {}
		    return null;
	
	}

static boolean verifySignedFile(String nomFichier, String signature, PublicKey publicPK) throws Exception{
	
	try {
		  			  
	      RandomAccessFile fichier = new RandomAccessFile(nomFichier, "r");
	      byte[] data = new byte[(int)fichier.length()];
	      fichier.readFully(data);
	      
	      // convertit les data en string
	      String chaine = new String(data);
	      
	      //affiche le contenu du fichier texte
	      System.out.printf("\n%s\n",chaine);
	      
	      fichier.close();
	      return ApiRSA.verify(chaine, signature, publicPK); // vérifie la signature
	    }
	    catch (FileNotFoundException e) {}
	    catch (IOException e) {}
	    return false;

}

	
}
