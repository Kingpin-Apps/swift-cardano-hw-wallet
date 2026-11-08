import Foundation
import SwiftCardanoCore
import CardanoHWKit

/// A ``HardwareSigner`` for Ledger devices. Drives the v8 SignTx dialogue over any ``LedgerTransport``
/// (BLE via the vendor SDK, or USB-HID), collects the per-path signatures, derives each witness
/// public key locally from the account xpub (Ledger never returns pubkeys), and assembles the
/// device's `TransactionWitnessSet` as CBOR hex — no private key ever leaves the device.
public actor LedgerSignSession: HardwareSigner {
    public nonisolated let deviceKind = HardwareDeviceKind.ledger

    private let transport: LedgerTransport
    private let network: LedgerNetwork
    private let options: LedgerSigningOptions
    /// Local public-key derivation from the imported account xpub. Required for ``sign(_:)``; a session
    /// used only for ``importAccount(network:accountIndex:)`` may omit it.
    private let derivation: PublicHDDerivation?

    public init(
        transport: LedgerTransport,
        network: LedgerNetwork,
        options: LedgerSigningOptions = .init(),
        derivation: PublicHDDerivation? = nil
    ) {
        self.transport = transport
        self.network = network
        self.options = options
        self.derivation = derivation
    }

    // MARK: - Import

    public func importAccount(network netId: NetworkId, accountIndex: Int) async throws -> HardwareAccountModel {
        let apdu = try LedgerAccountImport.getExtendedPublicKeyAPDU(accountIndex: accountIndex)
        let response = try await transport.exchange(apdu)
        return try LedgerAccountImport.parse(response: response, accountIndex: accountIndex, network: netId)
    }

    // MARK: - Sign

    public func sign(_ request: HardwareSignRequest) async throws -> String {
        guard let derivation else {
            throw LedgerError.app("LedgerSignSession.sign requires an account derivation (build the session with the imported account).")
        }

        let witnessPaths = try witnessPaths(for: request)
        let apdus = try LedgerCardanoSerializer.signTxAPDUs(
            request.unsigned, witnessPaths: witnessPaths, network: network, options: options,
            certificates: request.certificates, withdrawals: request.withdrawals
        )

        // The final `witnessPaths.count` APDUs are the per-path witness requests; everything before is
        // INIT + CBOR chunks (the last of which — CONFIRM — returns the device's tx hash).
        let streamCount = apdus.count - witnessPaths.count
        var deviceTxHash = Data()
        for index in 0..<streamCount {
            let response = try await transport.exchange(apdus[index])
            if index == streamCount - 1 { deviceTxHash = response }
        }

        // Integrity guard: the device's tx hash must equal our body hash, else its reconstructed CBOR
        // (and thus the signature) is over a different transaction — most likely a `tagCborSets`
        // mismatch. Fail loudly rather than submit an invalid witness.
        if deviceTxHash.count == LedgerAPDU.txHashLength {
            let expected = try request.unsigned.transactionBody.hash()
            guard deviceTxHash == expected else {
                throw LedgerError.app(
                    "Device tx hash \(deviceTxHash.toHex) ≠ expected \(expected.toHex) — transaction serialization mismatch (check LedgerSigningOptions.tagCborSets)."
                )
            }
        }

        var signatures: [Data] = []
        for index in streamCount..<apdus.count {
            let signature = try await transport.exchange(apdus[index])
            guard signature.count == LedgerAPDU.signatureLength else {
                throw LedgerError.malformedResponse("Witness signature was \(signature.count) bytes, expected \(LedgerAPDU.signatureLength).")
            }
            signatures.append(signature)
        }

        return try assembleWitnessSet(paths: witnessPaths, signatures: signatures, derivation: derivation)
    }

    // MARK: - Internals

    /// Unique witness paths (in order): the payment paths for spent UTxOs, then the stake paths any
    /// certificate / withdrawal is signed by — one witness per distinct key.
    private func witnessPaths(for request: HardwareSignRequest) throws -> [LedgerBIP32Path] {
        var seen = Set<String>()
        var paths: [LedgerBIP32Path] = []
        func add(_ pathString: String) throws {
            if seen.insert(pathString).inserted {
                paths.append(try LedgerBIP32Path(pathString))
            }
        }
        for utxo in request.spentUTxOs {
            let address: String
            do { address = try utxo.output.address.toBech32() }
            catch { throw LedgerError.app("A spent UTxO has an unencodable address: \(error)") }
            guard let pathString = request.addressPaths[address] else {
                throw LedgerError.app("No derivation path for input address \(address).")
            }
            try add(pathString)
        }
        for certificate in request.certificates { try add(certificate.stakePath) }
        for withdrawal in request.withdrawals { try add(withdrawal.stakePath) }
        guard !paths.isEmpty else {
            throw LedgerError.app("Sign request has no keys to witness.")
        }
        return paths
    }

    /// Pair each device signature with the locally derived public key at its path → a witness set.
    private func assembleWitnessSet(
        paths: [LedgerBIP32Path],
        signatures: [Data],
        derivation: PublicHDDerivation
    ) throws -> String {
        guard paths.count == signatures.count else {
            throw LedgerError.malformedResponse("Got \(signatures.count) signatures for \(paths.count) witness paths.")
        }
        var witnesses: [VerificationKeyWitness] = []
        for (path, signature) in zip(paths, signatures) {
            let publicKey = try witnessPublicKey(for: path, derivation: derivation)
            let vkey = try VerificationKeyType(from: .bytes(publicKey))
            witnesses.append(VerificationKeyWitness(vkey: vkey, signature: signature))
        }
        let set = TransactionWitnessSet(vkeyWitnesses: .nonEmptyOrderedSet(NonEmptyOrderedSet(witnesses)))
        do {
            return try set.toCBORHex()
        } catch {
            throw LedgerError.malformedResponse("Could not encode the assembled witness set: \(error)")
        }
    }

    /// The 32-byte public key at a witness path, derived from the account xpub (role 2 = stake key).
    private func witnessPublicKey(for path: LedgerBIP32Path, derivation: PublicHDDerivation) throws -> Data {
        guard let (role, index) = path.roleAndIndex else {
            throw LedgerError.app("Witness path \(path.indices) is too short to derive a key.")
        }
        if role == 2 {
            return try derivation.stakeVerificationKey(index: index).payload
        }
        return try derivation.paymentVerificationKey(role: role, index: index).payload
    }
}

extension LedgerSignSession: HardwareAddressVerifier {
    /// Derives the base address on the Ledger, checks it equals `expectedAddress`, then asks the
    /// device to display it so the user can confirm it matches the app.
    public func verifyAddress(_ expectedAddress: String, account: HardwareAccountModel, role: UInt32 = 0, index: UInt32 = 0, stakeIndex: UInt32 = 0) async throws {
        let spending = "\(account.accountPath)/\(role)/\(index)"
        let staking = "\(account.accountPath)/2/\(stakeIndex)"
        let returned = try await transport.exchange(LedgerAddressDerivation.apdu(
            p1: LedgerAddressDerivation.p1Return, networkId: network.networkId, spendingPath: spending, stakingPath: staking
        ))
        let deviceAddress: String
        do {
            deviceAddress = try Address(from: .bytes(returned)).toBech32()
        } catch {
            throw LedgerError.malformedResponse("Ledger returned an undecodable address: \(error)")
        }
        guard deviceAddress == expectedAddress else {
            throw HardwareWalletError.addressMismatch(expected: expectedAddress, device: deviceAddress)
        }
        _ = try await transport.exchange(LedgerAddressDerivation.apdu(
            p1: LedgerAddressDerivation.p1Display, networkId: network.networkId, spendingPath: spending, stakingPath: staking
        ))
    }
}
