package exam.exam_2025_january;

public class YourSolution {
    
	// Use this static variables to hardcode algorithm names and other important values
    private static final String HASH_ALGORITHM = "";
    private static final String HMAC_ALGORITHM = "";
    private static final String SHARED_SECRET = ""; // Secret key for HMAC authentication from the Excel file
    private static final String AES_ALGORITHM = "";
    private static final String FOLDER_PATH = "";


    // Step 1: Generate Digest values of all the files from the given folder
    public static void generateFilesDigest(String folderPath) throws Exception {

    }

    // Step 2: Generate HMAC-SHA256 authentication code
    public static void generateFilesHMAC(String folderPath, String secretKey) throws Exception {

    }
    

    // Step 3: Decrypt and verify the document
    public static boolean retrieveAndVerifyDocument(String file, String hashFile, String hmacFile, String secretKey) throws Exception {
        // Verify HMAC and digest for the given file
    	// Return true if the files has not been changed

    	
    	return false;
    }
    
    // Step 4: Generate AES key from the shared secret. See Excel for details
    public static byte[] generateSecretKey(String sharedSecret) throws Exception {
    	return null;
    }


    // Step 5: Encrypt document with AES and received key
    public static void encryptDocument(String filePath, byte[] key) throws Exception {

    }

    
    public static void main(String[] args) {


        try {
            // Step 1: Generate and store file digest
            generateFilesDigest(FOLDER_PATH);

            // Step 2: Generate and store HMAC for file authentication
            generateFilesHMAC(FOLDER_PATH, SHARED_SECRET);
            
            String filename = ""; //choose any message.txt file from the folder and test it
            String hashFile = ""; //the corresponding hash file
            String hmacFile = ""; //the corresponding hmac file
            
            // Step 3: Verify the document
            if (retrieveAndVerifyDocument(filename, hashFile, hmacFile, SHARED_SECRET)) {
                System.out.println("Document retrieved successfully. Integrity verified.");
            } else {
                System.out.println("Document verification failed!");
            }
            
            //Step 3: Change the file content and re-check it to be sure your solution is correct
            
            
            // Step 4: Get the derived key
            byte[] derivedKey = generateSecretKey(SHARED_SECRET);

            // Step 5: Encrypt the document
            encryptDocument(filename, derivedKey);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
