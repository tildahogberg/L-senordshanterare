using System;
namespace Lösenordshanterare
{
    internal class ServerFile
    {
        public byte[] IV { get; }
        public byte[] EncryptedVault { get; }

        public ServerFile(byte[] IV, byte[] EncryptedVault)
        {
            this.IV = IV;
            this.EncryptedVault = EncryptedVault;
        }
    }
}