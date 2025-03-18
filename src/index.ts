import { Agent } from '@openserv-labs/sdk'
import { z } from 'zod'
import axios from 'axios'
import { ethers } from 'ethers'
import 'dotenv/config'

interface AbiItem {
  type: string
  name?: string
  inputs?: { type: string; name?: string }[]
  outputs?: { type: string; name?: string }[]
  stateMutability?: string
  payable?: boolean
  constant?: boolean
}

// Contract Security Scanner Capability
const contractSecurityScannerCapability = {
  name: 'contract_security_scan',
  description: 'Scans smart contracts for security vulnerabilities and best practices',
  schema: z.object({
    contractAddress: z.string().describe('The smart contract address to analyze'),
    chainId: z
      .number()
      .optional()
      .describe('The blockchain network ID (defaults to Ethereum mainnet)')
  }),
  async run({ args }: { args: { contractAddress: string; chainId?: number } }) {
    const apiKey = process.env.ETHERSCAN_API_KEY
    const sourceCodeUrl = `https://api.etherscan.io/api?module=contract&action=getsourcecode&address=${args.contractAddress}&apikey=${apiKey}`
    const abiUrl = `https://api.etherscan.io/api?module=contract&action=getabi&address=${args.contractAddress}&apikey=${apiKey}`

    try {
      // Fetch contract source code
      const sourceResponse = await axios.get(sourceCodeUrl)
      const contractData = sourceResponse.data.result[0]

      // Check if contract is verified
      const isVerified = contractData.SourceCode !== ''

      // Initialize security indicators
      let hasAccessControl = false
      let hasOwnerFunction = false
      let hasEmergencyStop = false
      let usesReentrancyGuard = false
      let hasUpgradeability = false
      let hasTransferOwnership = false

      if (isVerified) {
        // Analyze source code for security patterns
        hasAccessControl =
          contractData.SourceCode.includes('onlyOwner') ||
          contractData.SourceCode.includes('Ownable') ||
          contractData.SourceCode.includes('AccessControl')

        hasEmergencyStop =
          contractData.SourceCode.includes('pause') || contractData.SourceCode.includes('Pausable')

        usesReentrancyGuard =
          contractData.SourceCode.includes('nonReentrant') ||
          contractData.SourceCode.includes('ReentrancyGuard')

        hasUpgradeability =
          contractData.SourceCode.includes('Proxy') ||
          contractData.SourceCode.includes('Upgradeable') ||
          contractData.SourceCode.includes('delegatecall')

        hasTransferOwnership =
          contractData.SourceCode.includes('transferOwnership') ||
          contractData.SourceCode.includes('Ownable')
      }

      // Fetch contract ABI for more detailed analysis
      const abiResponse = await axios.get(abiUrl)
      const abiData = JSON.parse(abiResponse.data.result)
      const abi = abiData as AbiItem[]

      // Check for owner functions in ABI
      hasOwnerFunction = abi.some(
        (item: AbiItem) =>
          (item.type === 'function' && item.name === 'owner') || item.name === 'getOwner'
      )

      // Check for other risky functions
      const hasSelfdestructFunction = abi.some(
        (item: AbiItem) =>
          item.type === 'function' && contractData.SourceCode.includes('selfdestruct')
      )

      const hasUncheckedTransfers =
        contractData.SourceCode.includes('transfer(') &&
        !contractData.SourceCode.includes('SafeERC20') &&
        !contractData.SourceCode.includes('require(')

      // Calculate risk score
      const riskScore = calculateSecurityRiskScore(
        isVerified,
        hasAccessControl,
        hasOwnerFunction,
        hasEmergencyStop,
        usesReentrancyGuard,
        hasSelfdestructFunction,
        hasUncheckedTransfers,
        hasUpgradeability
      )

      const riskLevel = getSecurityRiskLevel(riskScore)

      return JSON.stringify({
        contractAddress: args.contractAddress,
        chainId: args.chainId || 1, // Default to Ethereum mainnet
        riskLevel,
        riskScore,
        verificationStatus: isVerified ? 'Verified' : 'Unverified',
        securityIndicators: {
          hasAccessControl,
          hasOwnerFunction,
          hasEmergencyStop,
          usesReentrancyGuard,
          hasSelfdestructFunction,
          hasUncheckedTransfers,
          hasUpgradeability,
          hasTransferOwnership
        },
        recommendations: generateSecurityRecommendations(
          isVerified,
          hasAccessControl,
          hasEmergencyStop,
          usesReentrancyGuard,
          hasSelfdestructFunction,
          hasUncheckedTransfers
        ),
        scanTimestamp: new Date().toISOString()
      })
    } catch (error) {
      return JSON.stringify({
        error: 'Failed to scan contract',
        details: (error as Error).message
      })
    }
  }
}

function calculateSecurityRiskScore(
  isVerified: boolean,
  hasAccessControl: boolean,
  hasOwnerFunction: boolean,
  hasEmergencyStop: boolean,
  usesReentrancyGuard: boolean,
  hasSelfdestructFunction: boolean,
  hasUncheckedTransfers: boolean,
  hasUpgradeability: boolean
) {
  let score = 0

  // Unverified contracts are high risk
  if (!isVerified) score += 30

  // Positive security indicators reduce risk
  if (hasAccessControl) score -= 10
  if (hasEmergencyStop) score -= 5
  if (usesReentrancyGuard) score -= 10

  // Negative security indicators increase risk
  if (hasSelfdestructFunction) score += 20
  if (hasUncheckedTransfers) score += 15
  if (hasUpgradeability && !hasAccessControl) score += 15
  if (hasOwnerFunction && !hasAccessControl) score += 10

  // Ensure score is within 0-100 range
  return Math.max(0, Math.min(100, score + 50)) // Base score of 50
}

function getSecurityRiskLevel(score: number) {
  if (score >= 75) return 'High'
  if (score >= 40) return 'Medium'
  return 'Low'
}

function generateSecurityRecommendations(
  isVerified: boolean,
  hasAccessControl: boolean,
  hasEmergencyStop: boolean,
  usesReentrancyGuard: boolean,
  hasSelfdestructFunction: boolean,
  hasUncheckedTransfers: boolean
) {
  const recommendations = []

  if (!isVerified) {
    recommendations.push(
      'Contract source code is not verified. This makes security auditing difficult.'
    )
  }

  if (!hasAccessControl) {
    recommendations.push(
      "Implement proper access control mechanisms using OpenZeppelin's AccessControl or Ownable."
    )
  }

  if (!hasEmergencyStop) {
    recommendations.push(
      'Consider adding circuit breaker (emergency stop) functionality for emergency situations.'
    )
  }

  if (!usesReentrancyGuard) {
    recommendations.push('Implement reentrancy guards for functions that transfer ETH or tokens.')
  }

  if (hasSelfdestructFunction) {
    recommendations.push(
      'The contract contains selfdestruct functionality which could be dangerous if misused.'
    )
  }

  if (hasUncheckedTransfers) {
    recommendations.push(
      'Use SafeERC20 or check transfer return values to handle failed transfers properly.'
    )
  }

  return recommendations
}

// Wallet Analysis Capability
const walletAnalysisCapability = {
  name: 'analyze_wallet',
  description: 'Analyzes wallet activity for patterns and suspicious transactions',
  schema: z.object({
    walletAddress: z.string().describe('The wallet address to analyze'),
    timeframeInDays: z.number().default(30).describe('Number of days to analyze')
  }),
  async run({ args }: { args: { walletAddress: string; timeframeInDays: number } }) {
    const apiKey = process.env.ETHERSCAN_API_KEY
    const txListUrl = `https://api.etherscan.io/api?module=account&action=txlist&address=${args.walletAddress}&startblock=0&endblock=99999999&sort=desc&apikey=${apiKey}`
    const erc20TransfersUrl = `https://api.etherscan.io/api?module=account&action=tokentx&address=${args.walletAddress}&startblock=0&endblock=99999999&sort=desc&apikey=${apiKey}`

    try {
      // Calculate timestamp for timeframe start
      const timeframeStartTimestamp = Math.floor(Date.now() / 1000) - args.timeframeInDays * 86400

      // Fetch normal transactions
      const txResponse = await axios.get(txListUrl)
      const transactions = txResponse.data.result.filter(
        (tx: { timeStamp: string }) => parseInt(tx.timeStamp) >= timeframeStartTimestamp
      )

      // Fetch token transfers
      const tokenResponse = await axios.get(erc20TransfersUrl)
      const tokenTransfers = tokenResponse.data.result.filter(
        (tx: { timeStamp: string }) => parseInt(tx.timeStamp) >= timeframeStartTimestamp
      )

      // Calculate basic metrics
      const transactionCount = transactions.length
      const uniqueContractsInteracted = new Set(
        transactions
          .filter((tx: { to: string }) => tx.to)
          .map((tx: { to: string }) => tx.to.toLowerCase())
      ).size

      const uniqueTokensTransferred = new Set(
        tokenTransfers
          .filter((tx: { tokenSymbol: string }) => tx.tokenSymbol)
          .map((tx: { tokenSymbol: string }) => tx.tokenSymbol)
      )

      const uniqueTokensList = Array.from(uniqueTokensTransferred)

      // Calculate transaction volume in ETH
      const ethVolume = transactions.reduce((total: number, tx: { value: string }) => {
        return total + parseFloat(ethers.formatEther(tx.value))
      }, 0)

      // Identify potential suspicious patterns
      const largeTransactions = transactions.filter((tx: { value: string }) => {
        const value = parseFloat(ethers.formatEther(tx.value))
        return value > 10 // Transactions > 10 ETH
      })

      const unusualTokens = tokenTransfers.filter((tx: { tokenSymbol: string }) => {
        // This is a simplified check - in reality you'd compare against a database of known tokens
        return !['USDT', 'USDC', 'DAI', 'WETH', 'BTC', 'LINK'].includes(tx.tokenSymbol)
      })

      // Calculate activity patterns
      const firstTxTimestamp =
        transactions.length > 0
          ? parseInt(transactions[transactions.length - 1].timeStamp)
          : timeframeStartTimestamp

      const lastTxTimestamp =
        transactions.length > 0
          ? parseInt(transactions[0].timeStamp)
          : Math.floor(Date.now() / 1000)

      const activityDurationDays = (lastTxTimestamp - firstTxTimestamp) / 86400
      const activityFrequency =
        activityDurationDays > 0 ? transactionCount / activityDurationDays : 0

      return JSON.stringify({
        walletAddress: args.walletAddress,
        timeframeInDays: args.timeframeInDays,
        transactionCount,
        ethVolume: parseFloat(ethVolume.toFixed(4)),
        uniqueContractsInteracted,
        tokenActivity: {
          uniqueTokensCount: uniqueTokensList.length,
          tokensList: uniqueTokensList.slice(0, 10) // Limit to 10 tokens
        },
        activityMetrics: {
          firstTransaction: new Date(firstTxTimestamp * 1000).toISOString(),
          lastTransaction: new Date(lastTxTimestamp * 1000).toISOString(),
          averageTransactionsPerDay: parseFloat(activityFrequency.toFixed(2))
        },
        suspiciousIndicators: {
          largeTransactionsCount: largeTransactions.length,
          unusualTokensCount: unusualTokens.length,
          riskScore: calculateWalletRiskScore(
            transactionCount,
            largeTransactions.length,
            unusualTokens.length,
            uniqueContractsInteracted
          )
        },
        analysisTimestamp: new Date().toISOString()
      })
    } catch (error) {
      return JSON.stringify({
        error: 'Failed to analyze wallet',
        details: (error as Error).message
      })
    }
  }
}

function calculateWalletRiskScore(
  transactionCount: number,
  largeTransactionsCount: number,
  unusualTokensCount: number,
  uniqueContractsInteracted: number
) {
  // New wallets with high value transactions are riskier
  const newWalletRisk = transactionCount < 10 && largeTransactionsCount > 0 ? 30 : 0

  // Unusual token interaction risk
  const unusualTokenRisk = Math.min(30, unusualTokensCount * 5)

  // Contract interaction diversity - lower is riskier (less established pattern)
  const contractDiversityRisk = uniqueContractsInteracted < 3 ? 20 : 0

  // Add together with base risk
  const totalRisk = 20 + newWalletRisk + unusualTokenRisk + contractDiversityRisk

  // Return risk level
  if (totalRisk >= 70) return 'High'
  if (totalRisk >= 40) return 'Medium'
  return 'Low'
}

// Token Market Analysis Capability
const tokenMarketAnalysisCapability = {
  name: 'analyze_token_market',
  description: 'Analyzes token market data for trends and manipulation',
  schema: z.object({
    tokenAddress: z.string().describe('The token contract address'),
    timeframeInDays: z.number().default(7).describe('Number of days to analyze')
  }),
  async run({ args }: { args: { tokenAddress: string; timeframeInDays: number } }) {
    const apiKey = process.env.ETHERSCAN_API_KEY
    const tokenInfoUrl = `https://api.etherscan.io/api?module=token&action=tokeninfo&contractaddress=${args.tokenAddress}&apikey=${apiKey}`
    const transfersUrl = `https://api.etherscan.io/api?module=account&action=tokentx&contractaddress=${args.tokenAddress}&startblock=0&endblock=99999999&sort=desc&apikey=${apiKey}`

    try {
      // Calculate timestamp for timeframe start
      const timeframeStartTimestamp = Math.floor(Date.now() / 1000) - args.timeframeInDays * 86400

      // Fetch token info
      const tokenInfoResponse = await axios.get(tokenInfoUrl)
      const tokenInfo = tokenInfoResponse.data.result[0]

      // Fetch token transfers
      const transfersResponse = await axios.get(transfersUrl)
      const transfers = transfersResponse.data.result.filter(
        (tx: { timeStamp: string }) => parseInt(tx.timeStamp) >= timeframeStartTimestamp
      )

      // Calculate basic metrics
      const transferCount = transfers.length
      const uniqueAddresses = new Set([
        ...transfers.map((tx: { from: string }) => tx.from.toLowerCase()),
        ...transfers.map((tx: { to: string }) => tx.to.toLowerCase())
      ])
      const uniqueAddressCount = uniqueAddresses.size

      // Calculate holdings concentration
      interface AddressHoldings {
        [key: string]: number
      }

      // This is a simplified approach - in reality, you'd need to track balance changes
      const holdings: AddressHoldings = {}
      transfers.forEach((tx: { from: string; to: string; value: string; tokenDecimal: string }) => {
        const from = tx.from.toLowerCase()
        const to = tx.to.toLowerCase()
        const value = parseInt(tx.value) / Math.pow(10, parseInt(tx.tokenDecimal))

        if (!holdings[from]) holdings[from] = 0
        if (!holdings[to]) holdings[to] = 0

        holdings[from] -= value
        holdings[to] += value
      })

      // Find top holders
      const topHolders = Object.entries(holdings)
        .filter(([_, balance]) => balance > 0)
        .sort(([_, a], [__, b]) => b - a)
        .slice(0, 5)
        .map(([address, balance]) => ({ address, balance }))

      // Calculate concentration metrics
      const totalPositiveHoldings = Object.values(holdings)
        .filter(balance => balance > 0)
        .reduce((sum, balance) => sum + balance, 0)

      const topHoldersPercentage = topHolders.reduce(
        (sum, { balance }) => sum + (balance / totalPositiveHoldings) * 100,
        0
      )

      // Check for suspicious activities
      const transferFrequency = transferCount / args.timeframeInDays
      const suddenSpikes = identifyTransferSpikes(transfers)

      // Market manipulation risk assessment
      const manipulationRisk = assessMarketManipulationRisk(
        transferFrequency,
        topHoldersPercentage,
        suddenSpikes,
        uniqueAddressCount
      )

      return JSON.stringify({
        tokenAddress: args.tokenAddress,
        tokenInfo: {
          name: tokenInfo?.name || 'Unknown',
          symbol: tokenInfo?.symbol || 'Unknown',
          totalSupply: tokenInfo?.totalSupply || 'Unknown',
          decimals: tokenInfo?.divisor || '18'
        },
        marketMetrics: {
          transferCount,
          uniqueAddressCount,
          transfersPerDay: parseFloat(transferFrequency.toFixed(2)),
          topHoldersConcentration: parseFloat(topHoldersPercentage.toFixed(2)) + '%'
        },
        topHolders: topHolders.map(holder => ({
          address: holder.address,
          balance: parseFloat(holder.balance.toFixed(4)),
          percentage: parseFloat(((holder.balance / totalPositiveHoldings) * 100).toFixed(2)) + '%'
        })),
        marketManipulation: {
          risk: manipulationRisk,
          suspiciousActivityCount: suddenSpikes,
          recommendedAction: getMarketRecommendation(manipulationRisk)
        },
        analysisTimestamp: new Date().toISOString()
      })
    } catch (error) {
      return JSON.stringify({
        error: 'Failed to analyze token market',
        details: (error as Error).message
      })
    }
  }
}

function identifyTransferSpikes(transfers: any[]) {
  if (transfers.length < 10) return 0

  // Group transfers by hour
  const hourlyTransfers: { [key: string]: number } = {}
  transfers.forEach((tx: { timeStamp: string }) => {
    const hourTimestamp = Math.floor(parseInt(tx.timeStamp) / 3600) * 3600
    if (!hourlyTransfers[hourTimestamp]) hourlyTransfers[hourTimestamp] = 0
    hourlyTransfers[hourTimestamp]++
  })

  // Calculate average transfers per hour
  const hourlyValues = Object.values(hourlyTransfers)
  const averageTransfersPerHour =
    hourlyValues.reduce((sum, count) => sum + count, 0) / hourlyValues.length

  // Count hours with transfers > 3x average
  const spikeThreshold = averageTransfersPerHour * 3
  return hourlyValues.filter(count => count > spikeThreshold).length
}

function assessMarketManipulationRisk(
  transferFrequency: number,
  topHoldersPercentage: number,
  suddenSpikes: number,
  uniqueAddressCount: number
) {
  let riskScore = 0

  // High concentration is risky
  if (topHoldersPercentage > 80) riskScore += 30
  else if (topHoldersPercentage > 60) riskScore += 15

  // Unusual transfer activity
  if (transferFrequency > 1000) riskScore += 10
  if (suddenSpikes > 5) riskScore += 20

  // Low unique address count could indicate fake activity
  if (uniqueAddressCount < 20) riskScore += 20

  // Return risk level
  if (riskScore >= 40) return 'High'
  if (riskScore >= 20) return 'Medium'
  return 'Low'
}

function getMarketRecommendation(riskLevel: string) {
  switch (riskLevel) {
    case 'High':
      return 'Exercise extreme caution. Multiple indicators of potential market manipulation detected.'
    case 'Medium':
      return 'Proceed with caution and conduct additional research before engaging with this token.'
    default:
      return 'Standard market activity detected. Follow normal investment precautions.'
  }
}

// Create the blockchain security agent
const agent = new Agent({
  systemPrompt: `
    You are a blockchain security expert specialized in:
    1. Smart contract vulnerability analysis
    2. Detecting suspicious wallet activity
    3. Identifying market manipulation in token trading
    4. Assessing security risks in DeFi protocols
    5. Providing actionable security recommendations
    
    Analyze blockchain data carefully and provide clear, concise explanations 
    of security risks with specific recommendations.
  `,
  apiKey: process.env.OPENSERV_API_KEY
})

// Add all capabilities
agent.addCapabilities([
  contractSecurityScannerCapability,
  walletAnalysisCapability,
  tokenMarketAnalysisCapability
])

// Start the agent server
agent.start()

export default agent
