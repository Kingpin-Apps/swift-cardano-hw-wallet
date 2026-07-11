import Foundation
import SwiftCardanoCore
import SwiftCardanoChain
import SwiftCardanoTxBuilder

/// The unsigned transaction plus the UTxOs coin-selection actually chose to spend. A hardware sign
/// request needs both: the tx to sign, and the spent inputs (with their addresses / paths) so the
/// device knows which keys to sign with.
public struct UnsignedBuildResult: Sendable {
    public let transaction: Transaction
    public let spentUTxOs: [UTxO]

    public init(transaction: Transaction, spentUTxOs: [UTxO]) {
        self.transaction = transaction
        self.spentUTxOs = spentUTxOs
    }
}

/// Keyless unsigned-transaction build — device-neutral and iOS-safe. Mirrors the SDK's
/// `HardwareWallet.prepareSend` (`witnessOverride`, `potentialInputs`, `addOutput`, `build`,
/// `buildWitnessSet`) but takes candidate UTxOs explicitly and works with any `ChainContext`
/// (Koios/Blockfrost), so it runs on iOS with no `#if HARDWARE` / cardano-hw-cli dependency.
public enum UnsignedTxBuilder {

    /// Build an unsigned transaction spending from `candidateUTxOs` to `outputs`, returning change to
    /// `changeAddress`. `signerCount` sets the fee estimator's witness count (the number of distinct
    /// keys the device will add — 1 for a payment-only base-address send).
    public static func buildUnsigned(
        context: any ChainContext,
        candidateUTxOs: [UTxO],
        outputs: [TransactionOutput],
        changeAddress: Address,
        signerCount: Int = 1,
        ttl: SlotNumber? = nil,
        auxiliaryData: AuxiliaryData? = nil,
        certificates: [Certificate]? = nil,
        withdrawals: Withdrawals? = nil
    ) async throws -> UnsignedBuildResult {
        guard !candidateUTxOs.isEmpty else {
            throw HardwareWalletError.buildFailed("The account has no UTxOs to spend.")
        }
        // A staking-only transaction (certificate / withdrawal) can have no explicit outputs — change
        // covers the balance. Outputs are only required when there are no certs/withdrawals.
        let hasStakeActions = (certificates?.isEmpty == false) || (withdrawals != nil)
        guard !outputs.isEmpty || hasStakeActions else {
            throw HardwareWalletError.invalidRequest("A transaction needs at least one output.")
        }

        let builder = TxBuilder(context: context)
        builder.witnessOverride = max(1, signerCount)
        builder.potentialInputs = candidateUTxOs
        do {
            for output in outputs { _ = try builder.addOutput(output) }
        } catch {
            throw HardwareWalletError.invalidRequest("Invalid output: \(error)")
        }
        if let ttl { builder.ttl = ttl }
        builder.auxiliaryData = auxiliaryData
        builder.certificates = certificates
        builder.withdrawals = withdrawals

        let body: TransactionBody
        do {
            body = try await builder.build(changeAddress: changeAddress)
        } catch {
            let total = candidateUTxOs.reduce(Int64(0)) { $0 + $1.output.amount.coin }
            let required = outputs.reduce(Int64(0)) { $0 + $1.amount.coin }
            if total < required {
                throw HardwareWalletError.buildFailed("Not enough funds: need \(required), have \(total).")
            }
            throw HardwareWalletError.buildFailed("\(error)")
        }

        let witnessSet: TransactionWitnessSet
        do {
            witnessSet = try builder.buildWitnessSet()
        } catch {
            throw HardwareWalletError.buildFailed("witness set: \(error)")
        }

        let unsigned = Transaction(
            transactionBody: body,
            transactionWitnessSet: witnessSet,
            auxiliaryData: builder.auxiliaryData
        )

        let spent = spentUTxOs(chosenInputs: body.inputs.asArray, candidates: candidateUTxOs)
        return UnsignedBuildResult(transaction: unsigned, spentUTxOs: spent)
    }

    /// Resolve the chosen `TransactionInput`s back to their full `UTxO`s from the candidate set,
    /// preserving the transaction's input order.
    static func spentUTxOs(chosenInputs: [TransactionInput], candidates: [UTxO]) -> [UTxO] {
        let byInput: [TransactionInput: UTxO] = candidates.reduce(into: [:]) { $0[$1.input] = $1 }
        return chosenInputs.compactMap { byInput[$0] }
    }
}
