# ism-sap-c-cpp

## Configuration Steps

1. **Include Directories**
   - Go to your project settings in your IDE.
   - Navigate to:
     ```
     C/C++ -> Additional Include Directories
     ```
   - Add the following path:
     ```
     C:\openssl111l-build\include
     ```

2. **Linker Input**
   - Navigate to:
     ```
     Linker -> Input
     ```
   - Add the following library:
     ```
     C:\openssl111l-build\lib\libcrypto.lib
     ```

3. **Copy DLL File**
   - Locate the `libcrypto-1_1.dll` file from:
     ```
     C:\openssl111l-build\bin
     ```
   - Copy this file to the directory containing your project's executable file.

### Notes
- Ensure that all paths are correctly set based on your system's configuration.
- This configuration is for OpenSSL version 1.1.1.

By following these instructions, your project should be correctly configured to use OpenSSL.

