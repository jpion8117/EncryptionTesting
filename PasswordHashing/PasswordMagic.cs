using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text.Json;

namespace PasswordHashing
{
    internal class PasswordMagic
    {
        /// <summary>
        /// Stores the unencrypted password from the UnencryptedPw property
        /// </summary>
        private string _unencryptedPw = "";

        /// <summary>
        /// Stores the hashed password from the Password Hash property
        /// </summary>
        private string _passwordHash = "";
        
        /// <summary>
        /// Creates a new instance of the PasswordMagic object. Using the provided plaintext password
        /// </summary>
        /// <param name="unencryptedPw">Plaintext information to retrieve a hash for</param>
        public PasswordMagic(string unencryptedPw)
        {
            UnencryptedPw = unencryptedPw;
        }
        /// <summary>
        /// Returns the hashed version of the input information for compairison.
        /// </summary>
        public string PasswordHash
        {
            get { return _passwordHash; }
        }

        /// <summary>
        /// Used to set the unencrypted password and compute a new hash value associated with it.
        /// </summary>
        public string UnencryptedPw
        {
            set
            {
                //store the value of the unencrypted source data/password
                _unencryptedPw = value;

                //uses SHA512.Create to create select the appropriate implimentation of SHA512 for this system
                //automatically 
                using (SHA512 shaM = SHA512.Create())
                {
                    //store the data in a byte array
                    var toEncrypt = Encoding.Unicode.GetBytes(_unencryptedPw);
                    
                    //compute the hash using the SHA512 instance created earlier
                    var hash = shaM.ComputeHash(toEncrypt);

                    //convert the hash byte array to a string for easy storage.
                    _passwordHash = Encoding.Unicode.GetString(hash);
                }
            }
            get => _unencryptedPw;
        }
        
        /// <summary>
        /// Takes a password hash supplied to it and compaires it to the hash of this instance to see if there is a
        /// match. Returns true if hash supplied matches the hash of the current instance (IE passwords match)
        /// </summary>
        /// <param name="pwHash">Hash to compare</param>
        /// <returns>True if hashes match, false otherwise</returns>
        public bool Validate(string pwHash)
        {
            if (pwHash == PasswordHash)
                return true;
            else
                return false;
        }
    }
}
