using Net.Pkcs11Interop.HighLevelAPI;

namespace Net.Pkcs11Interop.X509Store
{
    internal class Pkcs11TokenFlags : ITokenFlags
    {
        public Pkcs11TokenFlags(ITokenFlags flags)
        {
            Flags = flags.Flags;
            Rng = flags.Rng;
            WriteProtected = flags.WriteProtected;
            LoginRequired = flags.LoginRequired;
            UserPinInitialized = flags.UserPinInitialized;
            RestoreKeyNotNeeded = flags.RestoreKeyNotNeeded;
            ClockOnToken = flags.ClockOnToken;
            ProtectedAuthenticationPath = flags.ProtectedAuthenticationPath;
            DualCryptoOperations = flags.DualCryptoOperations;
            TokenInitialized = flags.TokenInitialized;
            SecondaryAuthentication = flags.SecondaryAuthentication;
            UserPinCountLow = flags.UserPinCountLow;
            UserPinFinalTry = flags.UserPinFinalTry;
            UserPinLocked = flags.UserPinLocked;
            UserPinToBeChanged = flags.UserPinToBeChanged;
            SoPinCountLow = flags.SoPinCountLow;
            SoPinFinalTry = flags.SoPinFinalTry;
            SoPinLocked = flags.SoPinLocked;
            SoPinToBeChanged = flags.SoPinToBeChanged;
        }

        public ulong Flags { get; }
        public bool Rng { get; }
        public bool WriteProtected { get; }
        public bool LoginRequired { get; }
        public bool UserPinInitialized { get; }
        public bool RestoreKeyNotNeeded { get; }
        public bool ClockOnToken { get; }
        public bool ProtectedAuthenticationPath { get; }
        public bool DualCryptoOperations { get; }
        public bool TokenInitialized { get; }
        public bool SecondaryAuthentication { get; }
        public bool UserPinCountLow { get; }
        public bool UserPinFinalTry { get; }
        public bool UserPinLocked { get; }
        public bool UserPinToBeChanged { get; }
        public bool SoPinCountLow { get; }
        public bool SoPinFinalTry { get; }
        public bool SoPinLocked { get; }
        public bool SoPinToBeChanged { get; }
    }
}