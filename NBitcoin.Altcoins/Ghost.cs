using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using NBitcoin.RPC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;

namespace NBitcoin.Altcoins
{
    public class Ghost : NetworkSetBase
    {
        public static Ghost Instance { get; } = new Ghost();

        public override string CryptoCode => "GHOST";

        private Ghost()
        {

        }

        static uint ANON_MARKER = 0xffffffa0;

        //Format visual studio
        //{({.*?}), (.*?)}
        //Tuple.Create(new byte[]$1, $2)
        static Tuple<byte[], int>[] pnSeed6_main = {
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x95,0x1c,0x70,0xb9}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x5f,0xb3,0x90,0xcb}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x95,0x1c,0xac,0x84}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x95,0x1c,0xb7,0xb0}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x95,0x1c,0xb4,0x25}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x95,0x1c,0x13,0x7c}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x5f,0xb3,0xa9,0x2f}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x5f,0xb3,0xb8,0xc9}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x5f,0xb3,0xc0,0xd1}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x5f,0xb3,0xfa,0xd8}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2d,0x4c,0x57,0xa2}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x95,0x1c,0x0d,0x87}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2d,0x4c,0x27,0xbd}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xc0,0xf8,0x9b,0xa4}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x42,0x2a,0x68,0xe8}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x42,0x2a,0x77,0xae}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2d,0x4d,0xca,0xd9}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2d,0x4c,0xea,0x25}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x90,0xca,0x1b,0x40}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x6b,0xbf,0x39,0xd1}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x56,0xcf,0x05,0x51}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x18,0x8a,0x85,0x22}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x4e,0x8d,0xd8,0x0c}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xd1,0xa0,0x60,0x79}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x68,0xee,0xbb,0x24}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x4e,0x8d,0xd8,0x26}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x60,0x1e,0xc0,0xd5}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x60,0x1e,0xc7,0x08}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2d,0x20,0x45,0x2c}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x50,0xba,0xc8,0xef}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x89,0xdc,0x3c,0xca}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x88,0xf4,0x67,0xf0}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x6b,0xbf,0x2b,0x0f}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xc6,0x94,0x7a,0x9e}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x3e,0xab,0xac,0x3c}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2d,0x3f,0x41,0x2f}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x50,0xf0,0x14,0xbf}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xcf,0xf6,0x4c,0xb3}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x58,0x63,0xbe,0x9b}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xc0,0xf8,0x9c,0xcf}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x9b,0x8a,0x89,0xdb}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2d,0x20,0xae,0xef}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x8d,0xa4,0x3e,0x49}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xce,0xbd,0x9b,0xb4}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x5b,0xed,0x0c,0x32}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x36,0xc2,0xd7,0x2b}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x90,0xca,0x4a,0xbe}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xcf,0x94,0x73,0x2d}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x5f,0xb3,0x81,0x32}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xa4,0x84,0x61,0xce}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xca,0xb6,0x76,0x88}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x4e,0x8d,0xd2,0xce}, 51728),
    Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x58,0xcf,0x8d,0xfa}, 51728)

};
        static Tuple<byte[], int>[] pnSeed6_test = {

};

#pragma warning disable CS0618 // Type or member is obsolete
        public class GhostConsensusFactory : ConsensusFactory
        {
            private GhostConsensusFactory()
            {
            }

            public static GhostConsensusFactory Instance { get; } = new GhostConsensusFactory();

            public override BlockHeader CreateBlockHeader()
            {
                return new GhostBlockHeader();
            }
            public override Block CreateBlock()
            {
                return new GhostBlock(new GhostBlockHeader());
            }

            public override Transaction CreateTransaction()
            {
                return new GhostTransaction(this);
            }

            public override bool TryCreateNew(Type type, out IBitcoinSerializable result)
            {
                if (typeof(TxIn).GetTypeInfo().IsAssignableFrom(type.GetTypeInfo()))
                {
                    result = new GhostTxIn();
                    return true;
                }
                if (typeof(TxOut).GetTypeInfo().IsAssignableFrom(type.GetTypeInfo()))
                {
                    result = new GhostTxOut();
                    return true;
                }
                return base.TryCreateNew(type, out result);
            }
        }

        public class GhostBlockHeader : BlockHeader
        {
            protected uint256 hashWitnessMerkleRoot;

            public uint256 HashWitnessMerkleRoot
            {
                get
                {
                    return hashWitnessMerkleRoot;
                }
                set
                {
                    hashWitnessMerkleRoot = value;
                }
            }
            public override uint256 GetPoWHash()
            {
                var headerBytes = this.ToBytes();
                var h = NBitcoin.Crypto.SCrypt.ComputeDerivedKey(headerBytes, headerBytes, 1024, 1, 1, null, 32);
                return new uint256(h);
            }

            public override void ReadWrite(BitcoinStream stream)
            {
                stream.ReadWrite(ref nVersion);
                stream.ReadWrite(ref hashPrevBlock);
                stream.ReadWrite(ref hashMerkleRoot);
                stream.ReadWrite(ref hashWitnessMerkleRoot);
                stream.ReadWrite(ref nTime);
                stream.ReadWrite(ref nBits);
                stream.ReadWrite(ref nNonce);
            }
        }

        public class GhostBlock : Block
        {
            public GhostBlock(GhostBlockHeader header) : base(header)
            {

            }

            public override ConsensusFactory GetConsensusFactory()
            {
                return GhostConsensusFactory.Instance;
            }
        }

        public class GhostTransaction : Transaction
        {
            public GhostTransaction(ConsensusFactory consensusFactory)
            {
                _Factory = consensusFactory;
            }

            ConsensusFactory _Factory;
            public override ConsensusFactory GetConsensusFactory()
            {
                return _Factory;
            }

            protected new ushort nVersion = 1;

            public new ushort Version
            {
                get
                {
                    return nVersion;
                }
                set
                {
                    nVersion = value;
                }
            }
            public override void ReadWrite(BitcoinStream stream)
            {        
                stream.ReadWrite(ref nVersion);                    
                stream.ReadWriteStruct(ref nLockTime);

                stream.ReadWrite<TxInList, TxIn>(ref vin);
                vin.Transaction = this;

                stream.ReadWrite<TxOutList, TxOut>(ref vout);
                vout.Transaction = this;

                if (stream.Type != SerializationType.Hash) {
                    Witness wit = new Witness(Inputs);
                    try
                    {
                        wit.ReadWrite(stream);
                    } catch (FormatException e) {
                        Console.Out.WriteLine(e.Message);
                    }
                }


            }
        }

        public class GhostTxIn : TxIn
        {
            byte[][] data = null;

            public override void ReadWrite(BitcoinStream stream)
            {
                if (!stream.Serializing)
                    prevout = null;
                stream.ReadWrite(ref prevout);
                stream.ReadWrite(ref scriptSig);
                stream.ReadWrite(ref nSequence);


                if (prevout.N == ANON_MARKER) {
                    uint stack_size = stream.Serializing ? (uint) data.Length : 0;
                    stream.ReadWriteAsVarInt(ref stack_size);

                    if (!stream.Serializing) {
                        data = new byte[stack_size][];
                    }

                    for (int k = 0; k < stack_size; k++)
                    {
                        uint data_size = stream.Serializing ? (uint) data[k].Length : 0;
                        stream.ReadWriteAsVarInt(ref data_size);

                        byte[] data_stack = stream.Serializing ? data[k] : new byte[data_size];

                        if (data_size != 0) {
                            stream.ReadWrite(ref data_stack);
                        }

                        if (!stream.Serializing) {
                            data[k] = data_stack;
                        }
                    }
                }
            }
        }

        public class GhostTxOut : TxOut
        {
            enum Type { OUTPUT_NULL, OUTPUT_STANDARD, OUTPUT_CT, OUTPUT_RINGCT, OUTPUT_DATA };

            byte type = 0;

            public override void ReadWrite(BitcoinStream stream)
            {
                stream.ReadWrite(ref type);

                uint data_size = 0;

                switch(type) {
                    case (byte)Type.OUTPUT_STANDARD:
                        long value = Value.Satoshi;
                        stream.ReadWrite(ref value);
                        if (!stream.Serializing)
                            _Value = new Money(value);
                        stream.ReadWrite(ref publicKey);
                        break;
                    case (byte)Type.OUTPUT_CT:
                        byte[] valueCommitment = new byte[33];
                        stream.ReadWrite(ref valueCommitment);

                        stream.ReadWriteAsVarInt(ref data_size);
                        if (data_size != 0) {
                            byte[] data = new byte[data_size];
                            stream.ReadWrite(ref data);
                        }

                        stream.ReadWriteAsVarInt(ref data_size);
                        if (data_size != 0) {
                            byte[] script = new byte[data_size];
                            stream.ReadWrite(ref script);
                        }

                        stream.ReadWriteAsVarInt(ref data_size);
                        if (data_size != 0) {
                            byte[] rangeProof = new byte[data_size];
                            stream.ReadWrite(ref rangeProof);
                        }

                        break;
                    case (byte)Type.OUTPUT_RINGCT:
                        byte[] pubkey = new byte[33];
                        stream.ReadWrite(ref pubkey);

                        byte[] valueCommitment2 = new byte[33];
                        stream.ReadWrite(ref valueCommitment2);

                        stream.ReadWriteAsVarInt(ref data_size);
                        if (data_size != 0) {
                            byte[] data = new byte[data_size];
                            stream.ReadWrite(ref data);
                        }

                        stream.ReadWriteAsVarInt(ref data_size);
                        if (data_size != 0) {
                            byte[] rangeProof = new byte[data_size];
                            stream.ReadWrite(ref rangeProof);
                        }
                        break;
                    case (byte)Type.OUTPUT_DATA:
                        stream.ReadWriteAsVarInt(ref data_size);
                        if (data_size != 0) {
                            byte[] data = new byte[data_size];
                            stream.ReadWrite(ref data);
                        }
                        break;
                    default:
                        break;
                }
            }
        }

        public class GhostMainnetAddressStringParser : NetworkStringParser
        {
            public override bool TryParse<T>(string str, Network network, out T result)
            {
                if (str.StartsWith("XGHST", StringComparison.OrdinalIgnoreCase) && typeof(T) == typeof(BitcoinExtKey))
                {
                    try
                    {
                        var decoded = Encoders.Base58Check.DecodeData(str);
                        decoded[0] = 0x68;
                        decoded[1] = 0xDF;
                        decoded[2] = 0x7C;
                        decoded[3] = 0xBD;
                        result = (T)(object)new BitcoinExtKey(Encoders.Base58Check.EncodeData(decoded), network);
                        return true;
                    }
                    catch
                    {
                    }
                }
                if (str.StartsWith("PGHST", StringComparison.OrdinalIgnoreCase) && typeof(T) == typeof(BitcoinExtPubKey))
                {
                    try
                    {
                        var decoded = Encoders.Base58Check.DecodeData(str);
                        decoded[0] = 0x8E;
                        decoded[1] = 0x8E;
                        decoded[2] = 0xA8;
                        decoded[3] = 0xEA;
                        result = (T)(object)new BitcoinExtPubKey(Encoders.Base58Check.EncodeData(decoded), network);
                        return true;
                    }
                    catch
                    {
                    }
                }
                return base.TryParse(str, network, out result);
            }
        }

#pragma warning restore CS0618 // Type or member is obsolete

        protected override void PostInit()
        {
            RegisterDefaultCookiePath("Ghost", new FolderName() { TestnetFolder = "testnet" });
        }

        protected override NetworkBuilder CreateMainnet()
        {
            NetworkBuilder builder = new NetworkBuilder();
            builder.SetConsensus(new Consensus()
            {
                SubsidyHalvingInterval = 210000,
                MajorityEnforceBlockUpgrade = 750,
                MajorityRejectBlockOutdated = 950,
                MajorityWindow = 1000,
                BIP34Hash = new uint256("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"),
                PowLimit = new Target(new uint256("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),      
                PowTargetTimespan = TimeSpan.FromSeconds(24 * 60),
                PowTargetSpacing = TimeSpan.FromSeconds(120),
                PowAllowMinDifficultyBlocks = false,
                PowNoRetargeting = false,
                RuleChangeActivationThreshold = 1916,
                MinerConfirmationWindow = 2016,
                CoinbaseMaturity = 100,
                ConsensusFactory = GhostConsensusFactory.Instance
            })
            .SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 0x26 }) // G
            .SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 0x61 })
            .SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 0xA6 })
            .SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x68, 0xDF, 0x7C, 0xBD }) // PGHST
            .SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x8E, 0x8E, 0xA8, 0xEA }) // XGHST
            .SetBase58Bytes(Base58Type.STEALTH_ADDRESS, new byte[] { 0x14 })
            .SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("gp"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("gp"))
            .SetNetworkStringParser(new GhostMainnetAddressStringParser())
            .SetMagic(0xf2f3e1b4)                 
            .SetPort(51728)
            .SetRPCPort(51725)
            .SetMaxP2PVersion(90011)
            .SetName("ghost-main")
            .AddAlias("ghost-mainnet")
            .AddAlias("ghost-mainnet")
            .AddAlias("ghost-main")
            .AddDNSSeeds(new[]
            {
                 new DNSSeedData("ghostseeder.ghostbymcafee.com", "ghostseeder.ghostbymcafee.com"),
                 new DNSSeedData("ghostseeder.coldstake.io", "ghostseeder.coldstake.io"),
            })
            .AddSeeds(ToSeed(pnSeed6_main))
            .SetGenesis("a000000000000000000000000000000000000000000000000000000000000000000000001f12a2291c6a84e449ffd3b7f93d897abcc41e3ce2eaedf769ef58878bed6533c3fa5b3067b7d2406227696a9297f0db451e0c20d3c80894348b779a44ee4c9bd78dea5effff001fab78010001a00100000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4e04ffff001d01044442544320303030303030303030303030303030303030633637396263323230393637366430353132393833343632376337623163303264313031386232323463366633376a00ffffffff1401c006b568503e00001976a914ac91d9def79121740404da83c600d187e89f8aff88ac01c006b568503e00001976a9144d43e963865032057ef616caec9e086ff6120ac288ac01c006b568503e00001976a914b2671804429dc27f109da9c587487d014456764388ac01c006b568503e00001976a914f5a9f6f57a007a029e836a848eb4876dfa8e3a0388ac01c006b568503e00001976a9148837a52768d79e080d79b09cf4a116968ceef72588ac01c006b568503e00001976a914c7d1847cb9fb340415fa8baf45fca6f197f4332188ac01c006b568503e00001976a914dcd6e461bdad602cc1aa58a5d52e1e5967efa48e88ac01c006b568503e00001976a9149e322d2934db522f13a9a7c86226e4fa100aec6b88ac01c006b568503e00001976a9148d4dafe7bcf2d7572d39e3493dacbbc4c67278e188ac01c006b568503e00001976a914f859e9757a493aadf12e60896bbe8b9b39eb26d288ac01c006b568503e00001976a91481093899c94b6f86650ef57a8a4bcd724488bc2188ac01c006b568503e00001976a914a00c672cf0ae25d9d42c2350bbb08fb6df34478688ac01c006b568503e00001976a91459ca3ae2f992dc6a73ec668ac747a327a99adec088ac01c006b568503e00001976a914a43f74d1d773ff485dc157714e6ed8772c88e52388ac01c006b568503e00001976a914451d033e99f26e254e118ced3b6d6e709e80429d88ac01c006b568503e00001976a914686c7590c3418d0dc49f16cbbcfe6528905dd9b188ac01c006b568503e00001976a914d755c6410c5008f88771bba9879336a01208d88f88ac01c006b568503e00001976a9140c59e6e59b1fe7cd0361a193356c39d4202bf5ca88ac01c006b568503e00001976a914b9539acc18027f45f451c3567d47136e4aac681788ac01c006b568503e00001976a914d09288f9150d32166573cbeb0e7f34ef43403d2088ac0000");
            return builder;
        }

        protected override NetworkBuilder CreateTestnet()
        {
            NetworkBuilder builder = new NetworkBuilder();
            builder.SetConsensus(new Consensus()
            {
                SubsidyHalvingInterval = 210000,
                MajorityEnforceBlockUpgrade = 51,
                MajorityRejectBlockOutdated = 75,
                MajorityWindow = 144,
                PowLimit = new Target(new uint256("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
                PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60),
                PowTargetSpacing = TimeSpan.FromSeconds(10 * 60),
                PowAllowMinDifficultyBlocks = true,
                PowNoRetargeting = false,
                RuleChangeActivationThreshold = 1512,
                MinerConfirmationWindow = 2016,
                CoinbaseMaturity = 100,
                ConsensusFactory = GhostConsensusFactory.Instance
            })
            .SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 0x76 }) // p
            .SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 0x7a })
            .SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 0x2e })
            .SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0xe1, 0x42, 0x78, 0x00 }) // ppar
            .SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0x94, 0x78 }) // xpar
            .SetBase58Bytes(Base58Type.STEALTH_ADDRESS, new byte[] { 0x15 })
            .SetMagic(0x0b051108) 
            .SetPort(51728)
            .SetRPCPort(51725)
            .SetMaxP2PVersion(90011)
            .SetName("ghost-test")
            .AddAlias("ghost-testnet")
            .AddAlias("ghost-testnet")
            .AddAlias("ghost-test")
            .AddDNSSeeds(new[]
            {
                new DNSSeedData("ghost-testnetdns.mineit.io", "ghost-testnetdns.mineit.io"),
            })
            .AddSeeds(ToSeed(pnSeed6_test))
            .SetGenesis("a00000000000000000000000000000000000000000000000000000000000000000000000759477c0c8fb3f27c426f7e2b5d4bc4d18ac9ff2743e01695db5403f7e82aca4e1060ca2eef97af702abde3803d01451c2b30caf7d0b867d3de855ac207a91085136d05effff001f5835000001a00100000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4f04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b736a00ffffffff1401c0b6e588b93d00001976a9148ae2036c06028e20ac32e01bd59ed9e09291c6c588ac01c0b6e588b93d00001976a914c7c52417d63147ddd43f9449b19c0a286dad874088ac01c0b6e588b93d00001976a9140affbdd2a3f88716989388397bdce0923e482a2388ac01c0b6e588b93d00001976a9141ecc333c09a3eaccd0dcd1d57ff6109502b3aa6288ac01c0b6e588b93d00001976a9141c83b0ea73814a4c06f39680151afb5414f9c2db88ac01c0b6e588b93d00001976a914501c9c2b742c673b287fd001daab061a9a99028788ac01c0b6e588b93d00001976a914dc618eca61baa03fb2fc780fb02af59d428d52a188ac01c0b6e588b93d00001976a914f0bb2b0e5b978a50103c19d6726ad33fbcf2717288ac01c0b6e588b93d00001976a91491059d85a87905e3aeb5c07526b32d2443ccb16988ac01c0b6e588b93d00001976a914ef901834835e8f51519da5741bd5511dfdff22c688ac01c0b6e588b93d00001976a9143b5d7439fcca520ad989d49038bc9dc48397106088ac01c0b6e588b93d00001976a9141cb113bd0778fa09bbd4927411b7dba0a673f5c988ac01c0b6e588b93d00001976a91412e5e9ce93d416d5ec4127f0e1d682972c8e1ddc88ac01c0b6e588b93d00001976a9148848ae9c76af612cd4e41f8e073f47e432c774cb88ac01c0b6e588b93d00001976a9145619392124dc6a00243053742f3872fa0da270d988ac01c0b6e588b93d00001976a914babfa38ae73de9bb26fa21cf30dc535019e1833e88ac01c0b6e588b93d00001976a91414ea24f913c3af99e0d8744dd1405609426277a088ac01c0b6e588b93d00001976a91479f906021c2cbbe1c5405ca8a7f44548ee79a82f88ac01c0b6e588b93d00001976a914aca61ffbf935ec4bc102f6a3765a8e80408c1ecb88ac01c0b6e588b93d00001976a914c19ec5255e21e93347d2704d8430f4f8bdae7dc388ac0000");
            return builder;
        }

        protected override NetworkBuilder CreateRegtest()
        {
            NetworkBuilder builder = new NetworkBuilder();
            builder.SetConsensus(new Consensus()
            {
                SubsidyHalvingInterval = 150,
                MajorityEnforceBlockUpgrade = 51,
                MajorityRejectBlockOutdated = 75,
                MajorityWindow = 1000,
                PowLimit = new Target(new uint256("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
                PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60),
                PowTargetSpacing = TimeSpan.FromSeconds(10 * 60),
                PowAllowMinDifficultyBlocks = true,
                PowNoRetargeting = true,
                RuleChangeActivationThreshold = 108,
                MinerConfirmationWindow = 144,
                CoinbaseMaturity = 100,
                ConsensusFactory = GhostConsensusFactory.Instance
            })
            .SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 0x76 }) // p
            .SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 0x7a })
            .SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 0x2e })
            .SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0xe1, 0x42, 0x78, 0x00 }) // ppar
            .SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0x94, 0x78 }) // xpar
            .SetBase58Bytes(Base58Type.STEALTH_ADDRESS, new byte[] { 0x15 }) // T
            .SetMagic(0x0b110907)
            .SetPort(11928)
            .SetRPCPort(51926)
            .SetMaxP2PVersion(90011)
            .SetName("ghost-reg")
            .AddAlias("ghost-regnet")
            .AddAlias("ghost-regnet")
            .AddAlias("ghost-reg")
            .AddSeeds(ToSeed(pnSeed6_test))
            .SetGenesis("a00000000000000000000000000000000000000000000000000000000000000000000000e73c4282995b99070381d55b06bdac82b79f2236d470306ac7f28a20c75396f839963992f2e596ac79190e322a615eef7777000d71da94b74af391ff1a6ab636e622015cffff7f200100000001a00100000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4f04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b736a00ffffffff0f010010a5d4e80000001976a914585c2b3914d9ee51f8e710304e386531c3abcc8288ac010010a5d4e80000001976a914c33f3603ce7c46b423536f0434155dad8ee2aa1f88ac010010a5d4e80000001976a91472d83540ed1dcf28bfaca3fa2ed77100c280882588ac010010a5d4e80000001976a91469e4cc4c219d8971a253cd5db69a0c99c4a5659d88ac010010a5d4e80000001976a914eab5ed88d97e50c87615a015771e220ab0a0991a88ac010010a5d4e80000001976a914119668a93761a34a4ba1c065794b26733975904f88ac010010a5d4e80000001976a9146da49762a4402d199d41d5778fcb69de19abbe9f88ac010010a5d4e80000001976a91427974d10ff5ba65052be7461d89ef2185acbe41188ac010010a5d4e80000001976a91489ea3129b8dbf1238b20a50211d50d462a988f6188ac010010a5d4e80000001976a9143baab5b42a409b7c6848a95dfd06ff792511d56188ac010088526a740000001976a914649b801848cc0c32993fb39927654969a5af27b088ac010088526a740000001976a914d669de30fa30c3e64a0303cb13df12391a2f725688ac010088526a740000001976a914f0c0e3ebe4a1334ed6a5e9c1e069ef425c52993488ac010088526a740000001976a91427189afe71ca423856de5f17538a069f2238542288ac010088526a740000001976a9140e7f6fe0c4a5a6a9bfd18f7effdd5898b1f40b8088ac0000");
            return builder;
        }
    }
}