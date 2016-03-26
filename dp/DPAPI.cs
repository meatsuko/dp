using System;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;

public class DPAPI
{
    [DllImport("crypt32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    private static extern bool CryptUnprotectData(ref DATA_BLOB pCipherText,
                                ref string pszDescription,
                                ref DATA_BLOB pEntropy,
                                    IntPtr pReserved,
                                ref CRYPTPROTECT_PROMPTSTRUCT pPrompt,
                                    int dwFlags,
                                ref DATA_BLOB pPlainText);

    // BLOB structure used to pass data to DPAPI functions.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    // Prompt structure to be used for required parameters.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct CRYPTPROTECT_PROMPTSTRUCT
    {
        public int cbSize;
        public int dwPromptFlags;
        public IntPtr hwndApp;
        public string szPrompt;
    }

    // Wrapper for the NULL handle or pointer.
    static private IntPtr NullPtr = ((IntPtr)((int)(0)));

    // DPAPI key initialization flags.
    private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;
    private const int CRYPTPROTECT_LOCAL_MACHINE = 0x4;

    /// <summary>
    /// Initializes empty prompt structure.
    /// </summary>
    /// <param name="ps">
    /// Prompt parameter (which we do not actually need).
    /// </param>
    private static void InitPrompt(ref CRYPTPROTECT_PROMPTSTRUCT ps)
    {
        ps.cbSize = Marshal.SizeOf(
                                  typeof(CRYPTPROTECT_PROMPTSTRUCT));
        ps.dwPromptFlags = 0;
        ps.hwndApp = NullPtr;
        ps.szPrompt = null;
    }

    /// <summary>
    /// Initializes a BLOB structure from a byte array.
    /// </summary>
    /// <param name="data">
    /// Original data in a byte array format.
    /// </param>
    /// <param name="blob">
    /// Returned blob structure.
    /// </param>
    private static void InitBLOB(byte[] data, ref DATA_BLOB blob)
    {
        // Use empty array for null parameter.
        if (data == null)
            data = new byte[0];

        // Allocate memory for the BLOB data.
        blob.pbData = Marshal.AllocHGlobal(data.Length);

        // Make sure that memory allocation was successful.
        if (blob.pbData == IntPtr.Zero)
            throw new Exception(
                "Unable to allocate data buffer for BLOB structure.");

        // Specify number of bytes in the BLOB.
        blob.cbData = data.Length;

        // Copy data from original source to the BLOB structure.
        Marshal.Copy(data, 0, blob.pbData, data.Length);
    }

    // Flag indicating the type of key. DPAPI terminology refers to
    // key types as user store or machine store.
    public enum KeyType { UserKey = 1, MachineKey };

    // It is reasonable to set default key type to user key.
    private static KeyType defaultKeyType = KeyType.UserKey;

    /// <summary>
    /// Calls DPAPI CryptUnprotectData to decrypt ciphertext bytes.
    /// </summary>
    /// <param name="cipherTextBytes">
    /// Encrypted data.
    /// </param>
    /// <param name="entropyBytes">
    /// Optional entropy, which is required if it was specified during
    /// encryption.
    /// </param>
    /// <param name="description">
    /// Returned description of data specified during encryption.
    /// </param>
    /// <returns>
    /// Decrypted data bytes.
    /// </returns>
    /// <remarks>
    /// When decrypting data, it is not necessary to specify which
    /// type of encryption key to use: user-specific or
    /// machine-specific; DPAPI will figure it out by looking at
    /// the signature of encrypted data.
    /// </remarks>
    public static byte[] Decrypt(byte[] cipherTextBytes,
                                     byte[] entropyBytes,
                                 out string description)
    {
        // Create BLOBs to hold data.
        DATA_BLOB plainTextBlob = new DATA_BLOB();
        DATA_BLOB cipherTextBlob = new DATA_BLOB();
        DATA_BLOB entropyBlob = new DATA_BLOB();

        // We only need prompt structure because it is a required
        // parameter.
        CRYPTPROTECT_PROMPTSTRUCT prompt =
                                  new CRYPTPROTECT_PROMPTSTRUCT();
        InitPrompt(ref prompt);

        // Initialize description string.
        description = String.Empty;

        try
        {
            // Convert ciphertext bytes into a BLOB structure.
            try
            {
                InitBLOB(cipherTextBytes, ref cipherTextBlob);
            }
            catch (Exception ex)
            {
                throw new Exception(
                    "Cannot initialize ciphertext BLOB.", ex);
            }

            // Convert entropy bytes into a BLOB structure.
            try
            {
                InitBLOB(entropyBytes, ref entropyBlob);
            }
            catch (Exception ex)
            {
                throw new Exception(
                    "Cannot initialize entropy BLOB.", ex);
            }

            // Disable any types of UI. CryptUnprotectData does not
            // mention CRYPTPROTECT_LOCAL_MACHINE flag in the list of
            // supported flags so we will not set it up.
            int flags = CRYPTPROTECT_UI_FORBIDDEN;

            // Call DPAPI to decrypt data.
            bool success = CryptUnprotectData(ref cipherTextBlob,
                                              ref description,
                                              ref entropyBlob,
                                                  IntPtr.Zero,
                                              ref prompt,
                                                  flags,
                                              ref plainTextBlob);

            // Check the result.
            if (!success)
            {
                // If operation failed, retrieve last Win32 error.
                int errCode = Marshal.GetLastWin32Error();

                // Win32Exception will contain error message corresponding
                // to the Windows error code.
                throw new Exception(
                    "CryptUnprotectData failed.", new Win32Exception(errCode));
            }

            // Allocate memory to hold plaintext.
            byte[] plainTextBytes = new byte[plainTextBlob.cbData];

            // Copy ciphertext from the BLOB to a byte array.
            Marshal.Copy(plainTextBlob.pbData,
                         plainTextBytes,
                         0,
                         plainTextBlob.cbData);

            // Return the result.
            return plainTextBytes;
        }
        catch (Exception ex)
        {
            throw new Exception("DPAPI was unable to decrypt data.", ex);
        }
        // Free all memory allocated for BLOBs.
        finally
        {
            if (plainTextBlob.pbData != IntPtr.Zero)
                Marshal.FreeHGlobal(plainTextBlob.pbData);

            if (cipherTextBlob.pbData != IntPtr.Zero)
                Marshal.FreeHGlobal(cipherTextBlob.pbData);

            if (entropyBlob.pbData != IntPtr.Zero)
                Marshal.FreeHGlobal(entropyBlob.pbData);
        }
    }
}