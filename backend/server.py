from fastapi import FastAPI, APIRouter, UploadFile, File, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, FileResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime
import re
import json
import asyncio
import io
import base64
import tempfile

# PDF generation imports
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="RustProof", description="Professional Solana Security Analysis Platform", version="1.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

# Enhanced Models
class Vulnerability(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    severity: str  # Critical, High, Medium, Low
    category: str
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    fix_suggestion: str
    fix_example: str
    cwe_id: Optional[str] = None
    impact_score: int = 0
    exploitability: str = "Unknown"
    real_world_example: Optional[str] = None

class SecurityMetrics(BaseModel):
    total_lines_analyzed: int = 0
    complexity_score: int = 0
    attack_surface_score: int = 0
    business_logic_score: int = 0
    defi_risk_score: int = 0

class ComplianceReport(BaseModel):
    soc2_score: int = 0
    nist_score: int = 0
    owasp_score: int = 0
    missing_controls: List[str] = []
    recommendations: List[str] = []

class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: str  # pending, scanning, completed, failed
    security_score: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    file_count: int = 0
    vulnerabilities: List[Vulnerability] = []
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    # Enhanced analytics
    security_metrics: SecurityMetrics = SecurityMetrics()
    compliance_report: ComplianceReport = ComplianceReport()
    risk_assessment: str = "Unknown"
    remediation_priority: List[str] = []
    
    # Session tracking
    session_id: Optional[str] = None
    file_name: Optional[str] = None

class SecurityRule(BaseModel):
    id: str
    name: str
    pattern: str
    severity: str
    category: str
    description: str
    fix_example: str
    cwe_id: Optional[str] = None
    impact_description: str = ""
    exploitability: str = "Medium"
    real_world_example: Optional[str] = None
    prevention_strategies: List[str] = []

# RustProof Security Rules - Professional Grade (60+ Rules)
RUSTPROOF_SECURITY_RULES = [
    # Critical Access Control Vulnerabilities
    SecurityRule(
        id="RP-001",
        name="Missing Signer Authorization",
        pattern=r'pub\s+fn\s+\w+\s*\([^)]*Context<[^>]+>[^)]*\)\s*->\s*Result<[^>]*>\s*\{[^}]*(?!.*is_signer)[^}]*\}',
        severity="Critical",
        category="Access Control",
        description="Function modifies state without verifying the caller is authorized",
        fix_example="require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);",
        cwe_id="CWE-862",
        impact_description="Complete bypass of authorization, allowing unauthorized state modifications",
        exploitability="High",
        real_world_example="Similar to the Wormhole bridge exploit where missing signer checks led to $320M loss",
        prevention_strategies=["Always check is_signer for state-modifying functions", "Use require! macros for access control", "Implement multi-sig for critical operations"]
    ),
    SecurityRule(
        id="RP-002", 
        name="Integer Overflow Vulnerability",
        pattern=r'(\w+\s*\+=\s*\w+|\w+\s*=\s*\w+\s*\+\s*\w+)(?!.*checked_add|.*saturating_add)',
        severity="High",
        category="Arithmetic",
        description="Arithmetic operation without overflow protection",
        fix_example="vault.balance = vault.balance.checked_add(amount).ok_or(ErrorCode::Overflow)?;",
        cwe_id="CWE-190",
        impact_description="Token supply manipulation, infinite minting vulnerabilities",
        exploitability="High",
        real_world_example="Similar overflow vulnerabilities have led to token supply inflation attacks",
        prevention_strategies=["Use checked_add/checked_sub", "Implement SafeMath patterns", "Add bounds checking"]
    ),
    SecurityRule(
        id="RP-003",
        name="Account Ownership Bypass", 
        pattern=r'pub\s+fn\s+\w+[^{]*\{(?!.*owner\s*==|.*key\(\)\s*==)[^}]*ctx\.accounts\.\w+[^}]*\}',
        severity="Critical",
        category="Access Control", 
        description="Account used without verifying ownership",
        fix_example="require!(ctx.accounts.token_account.owner == ctx.accounts.authority.key(), ErrorCode::InvalidOwner);",
        cwe_id="CWE-863",
        impact_description="Unauthorized access to user accounts and funds",
        exploitability="High",
        prevention_strategies=["Verify account ownership before use", "Check program ID ownership", "Use account constraints"]
    ),
    SecurityRule(
        id="RP-004",
        name="PDA Bump Manipulation",
        pattern=r'fn\s+\w+[^{]*bump:\s*u8[^{]*\{[^}]*find_program_address[^}]*&\[bump\]',
        severity="Critical",
        category="Solana Specific",
        description="Using user-provided bump instead of canonical bump seed",
        fix_example="let (expected_pda, canonical_bump) = Pubkey::find_program_address(seeds, program_id);\nrequire!(bump == canonical_bump, ErrorCode::InvalidBump);",
        cwe_id="CWE-20",
        impact_description="PDA manipulation and unauthorized account access",
        exploitability="High",
        prevention_strategies=["Use ctx.bumps for canonical bumps", "Validate bump seeds", "Never trust user-provided bumps"]
    ),
    SecurityRule(
        id="RP-005",
        name="Oracle Price Manipulation",
        pattern=r'price_feed\.get_price\(\)(?!.*staleness|.*confidence|.*validation)',
        severity="Critical",
        category="Oracle",
        description="Using oracle price without staleness or confidence validation",
        fix_example="let price_data = price_feed.get_price()?;\nrequire!(clock.unix_timestamp - price_data.timestamp < MAX_STALENESS, ErrorCode::StalePrice);",
        cwe_id="CWE-20",
        impact_description="Price manipulation attacks and liquidation cascades",
        exploitability="High",
        prevention_strategies=["Check price staleness", "Validate confidence intervals", "Use multiple oracle sources"]
    ),
    
    # DeFi-Specific Vulnerabilities
    SecurityRule(
        id="RP-006",
        name="Slippage Protection Missing",
        pattern=r'let\s+output\s*=\s*input\s*\*\s*\w+(?!.*min_output|.*slippage)',
        severity="High",
        category="DeFi",
        description="Token swap without slippage protection",
        fix_example="require!(output >= min_output_amount, ErrorCode::SlippageExceeded);",
        cwe_id="CWE-682",
        impact_description="Sandwich attacks and MEV extraction",
        exploitability="High",
        prevention_strategies=["Implement slippage bounds", "Add minimum output checks", "Use time-based protection"]
    ),
    SecurityRule(
        id="RP-007",
        name="Flash Loan Atomicity Failure",
        pattern=r'(?:borrow|flashloan)[^;]*;(?!.*repay|.*return)',
        severity="High",
        category="DeFi",
        description="Flash loan without atomic repayment enforcement",
        fix_example="Ensure flash loan repayment within same transaction using proper validation",
        cwe_id="CWE-362",
        impact_description="Flash loan attacks and protocol manipulation",
        exploitability="High",
        prevention_strategies=["Enforce atomic repayment", "Add reentrancy protection", "Validate loan conditions"]
    ),
    SecurityRule(
        id="RP-008",
        name="MEV Extraction Vector",
        pattern=r'pub\s+fn\s+swap[^{]*\{(?!.*deadline|.*private)',
        severity="Medium",
        category="DeFi",
        description="Public swap function vulnerable to MEV extraction",
        fix_example="Add deadline parameter and consider private mempool or commit-reveal schemes",
        cwe_id="CWE-362",
        impact_description="Front-running and sandwich attacks",
        exploitability="High",
        prevention_strategies=["Add transaction deadlines", "Use commit-reveal schemes", "Implement private mempools"]
    ),
    
    # Advanced Solana Patterns
    SecurityRule(
        id="RP-009",
        name="Close Authority Bypass",
        pattern=r'#\[account\([^)]*close\s*=\s*\w+[^)]*\)\](?!.*has_one|.*constraint)',
        severity="Critical",
        category="Account Management",
        description="Account closing without proper authority validation",
        fix_example="#[account(mut, close = destination, has_one = authority)]",
        cwe_id="CWE-862",
        impact_description="Unauthorized account closure and fund drainage",
        exploitability="High",
        prevention_strategies=["Add authority constraints to close", "Validate close destination", "Implement proper access control"]
    ),
    SecurityRule(
        id="RP-010",
        name="CPI Privilege Escalation",
        pattern=r'invoke\([^)]*\)(?!.*owner\s*==|.*program_id)',
        severity="Critical",
        category="Cross Program",
        description="Cross-program invocation without proper account validation",
        fix_example="require!(account.owner == expected_program_id, ErrorCode::InvalidProgramId);\ninvoke(&instruction, accounts)?;",
        cwe_id="CWE-863",
        impact_description="Privilege escalation through malicious programs",
        exploitability="High",
        prevention_strategies=["Validate program IDs before CPI", "Check account ownership", "Use trusted program lists"]
    ),
    
    # Additional Security Rules (continuing to 60+ total)
    SecurityRule(
        id="RP-011",
        name="Unsafe Error Handling",
        pattern=r'\.unwrap\(\)',
        severity="Medium",
        category="Error Handling",
        description="Using unwrap() can cause panics and program crashes",
        fix_example="Use .ok_or(ErrorCode::SomeError)? or .expect(\"meaningful message\") instead",
        cwe_id="CWE-248",
        impact_description="Program crashes and DoS vulnerabilities",
        exploitability="Low",
        prevention_strategies=["Use proper error handling", "Replace unwrap with ok_or", "Add panic safety checks"]
    ),
    SecurityRule(
        id="RP-012",
        name="Division by Zero Risk", 
        pattern=r'\/(?!\*)[^\/\n]*(?<!\*)\/',
        severity="Medium",
        category="Arithmetic",
        description="Division operation without zero check",
        fix_example="require!(divisor != 0, ErrorCode::DivisionByZero);\nlet result = numerator / divisor;",
        cwe_id="CWE-369",
        impact_description="Program crashes and transaction failures",
        exploitability="Low",
        prevention_strategies=["Check for zero before division", "Use safe division functions", "Add input validation"]
    ),
    SecurityRule(
        id="RP-013",
        name="Clock Manipulation Attack",
        pattern=r'Clock::get\(\)\?\.unix_timestamp(?!.*staleness|.*validation)',
        severity="Medium",
        category="Oracle/Time",
        description="Direct clock usage without validation allows time manipulation",
        fix_example="let clock = Clock::get()?;\nrequire!(clock.unix_timestamp >= last_update + MIN_TIME_DIFF, ErrorCode::TimestampTooEarly);",
        cwe_id="CWE-367",
        impact_description="Time-based attack vectors and timestamp manipulation",
        exploitability="Medium",
        prevention_strategies=["Add timestamp validation", "Use relative time checks", "Implement staleness protection"]
    ),
    SecurityRule(
        id="RP-014",
        name="Liquidation Manipulation",
        pattern=r'collateral_ratio\s*<\s*LIQUIDATION_THRESHOLD(?!.*grace_period|.*multiple_oracles)',
        severity="High",
        category="DeFi",
        description="Liquidation trigger without manipulation protection",
        fix_example="Add grace periods and use multiple oracle sources for liquidation decisions",
        cwe_id="CWE-682",
        impact_description="Liquidation manipulation and cascade failures",
        exploitability="High",
        prevention_strategies=["Add grace periods", "Use multiple oracles", "Implement liquidation delays"]
    ),
    SecurityRule(
        id="RP-015",
        name="Governance Attack Vector",
        pattern=r'voting_power[^;]*;(?!.*stake_time|.*minimum_stake)',
        severity="High",
        category="Governance",
        description="Governance voting without proper stake validation",
        fix_example="require!(stake_amount >= MIN_STAKE && stake_time >= MIN_LOCK_PERIOD, ErrorCode::InsufficientStake);",
        cwe_id="CWE-863",
        impact_description="Governance manipulation and hostile takeovers",
        exploitability="Medium",
        prevention_strategies=["Validate stake amounts", "Add time locks", "Implement voting delays"]
    ),
    SecurityRule(
        id="RP-016",
        name="Resource Exhaustion Risk",
        pattern=r'for\s+\w+\s+in\s+\w+(?!.*\.take\(|.*limit)',
        severity="Medium",
        category="Performance",
        description="Unbounded loop vulnerable to resource exhaustion",
        fix_example="for item in items.iter().take(MAX_ITERATIONS) { ... }",
        cwe_id="CWE-400",
        impact_description="DoS attacks through resource exhaustion",
        exploitability="Medium",
        prevention_strategies=["Add iteration limits", "Use bounded collections", "Implement gas limits"]
    ),
    SecurityRule(
        id="RP-017",
        name="Type Confusion Attack",
        pattern=r'std::mem::transmute|unsafe\s*{[^}]*as\s+\w+',
        severity="Critical",
        category="Memory Safety",
        description="Unsafe type casting without proper validation",
        fix_example="Use safe casting with proper type validation and bounds checking",
        cwe_id="CWE-843",
        impact_description="Memory corruption and arbitrary code execution",
        exploitability="High",
        prevention_strategies=["Avoid unsafe operations", "Use safe type casting", "Add type validation"]
    ),
    SecurityRule(
        id="RP-018",
        name="Rent Exemption Bypass",
        pattern=r'\.lamports\(\)\s*<\s*rent\.minimum_balance\(',
        severity="Low",
        category="Account Management", 
        description="Account may not be rent exempt, vulnerable to rent collection",
        fix_example="require!(account.lamports() >= rent.minimum_balance(account.data_len()), ErrorCode::NotRentExempt);",
        cwe_id="CWE-20",
        impact_description="Account closure due to insufficient rent",
        exploitability="Low",
        prevention_strategies=["Ensure rent exemption", "Check minimum balance", "Add rent protection"]
    ),
    SecurityRule(
        id="RP-019",
        name="Metadata Manipulation",
        pattern=r'metadata\.\w+\s*=\s*\w+(?!.*authority|.*validation)',
        severity="Medium",
        category="NFT/Token",
        description="Metadata modification without proper authorization",
        fix_example="require!(metadata.update_authority == authority.key(), ErrorCode::UnauthorizedUpdate);",
        cwe_id="CWE-862",
        impact_description="NFT/token metadata manipulation",
        exploitability="Medium",
        prevention_strategies=["Validate update authority", "Add metadata locks", "Implement update permissions"]
    ),
    SecurityRule(
        id="RP-020",
        name="State Machine Violation",
        pattern=r'state\s*=\s*\w+(?!.*previous_state|.*transition_valid)',
        severity="Medium",
        category="State Management",
        description="State transition without validation of previous state",
        fix_example="require!(is_valid_transition(current_state, new_state), ErrorCode::InvalidTransition);",
        cwe_id="CWE-754",
        impact_description="Invalid state transitions and protocol violations",
        exploitability="Medium",
        prevention_strategies=["Validate state transitions", "Implement state machines", "Add transition guards"]
    ),
    
    # NEW ADVANCED SOLANA VULNERABILITIES (RP-021 to RP-060)
    SecurityRule(
        id="RP-021",
        name="Token Account Freeze Authority Bypass",
        pattern=r'token\.freeze_account\([^)]*\)(?!.*freeze_authority)',
        severity="High",
        category="Token Security",
        description="Token freeze operation without proper freeze authority validation",
        fix_example="require!(mint.freeze_authority == Some(authority.key()), ErrorCode::InvalidFreezeAuthority);",
        cwe_id="CWE-862",
        impact_description="Unauthorized token account freezing",
        exploitability="High",
        prevention_strategies=["Validate freeze authority", "Check authority permissions", "Use proper token constraints"]
    ),
    SecurityRule(
        id="RP-022",
        name="Mint Authority Escalation",
        pattern=r'token\.mint_to\([^)]*\)(?!.*mint_authority)',
        severity="Critical",
        category="Token Security",
        description="Token minting without proper mint authority validation",
        fix_example="require!(mint.mint_authority == Some(authority.key()), ErrorCode::InvalidMintAuthority);",
        cwe_id="CWE-862",
        impact_description="Unauthorized token minting and supply inflation",
        exploitability="High",
        prevention_strategies=["Validate mint authority", "Check minting permissions", "Implement supply caps"]
    ),
    SecurityRule(
        id="RP-023",
        name="Cross-Chain Bridge Verification Bypass",
        pattern=r'bridge\.verify_signature\([^)]*\)(?!.*multiple_validators)',
        severity="Critical",
        category="Bridge Security",
        description="Cross-chain bridge signature verification without multiple validator consensus",
        fix_example="require!(verified_signatures >= MIN_VALIDATOR_THRESHOLD, ErrorCode::InsufficientValidators);",
        cwe_id="CWE-345",
        impact_description="Bridge exploit through signature manipulation",
        exploitability="High",
        prevention_strategies=["Require multiple validator signatures", "Implement threshold consensus", "Add signature aggregation"]
    ),
    SecurityRule(
        id="RP-024",
        name="Staking Delegation Authority Bypass",
        pattern=r'stake\.delegate\([^)]*\)(?!.*stake_authority)',
        severity="High",
        category="Staking Security",
        description="Stake delegation without proper stake authority validation",
        fix_example="require!(stake_account.authorized.staker == authority.key(), ErrorCode::InvalidStakeAuthority);",
        cwe_id="CWE-862",
        impact_description="Unauthorized stake delegation and validator manipulation",
        exploitability="High",
        prevention_strategies=["Validate stake authority", "Check delegation permissions", "Implement delegation limits"]
    ),
    SecurityRule(
        id="RP-025",
        name="Validator Commission Manipulation",
        pattern=r'validator\.commission\s*=\s*\w+(?!.*commission_cap|.*rate_limit)',
        severity="Medium",
        category="Validator Security",
        description="Validator commission change without rate limiting or caps",
        fix_example="require!(new_commission <= MAX_COMMISSION && rate_limited, ErrorCode::CommissionTooHigh);",
        cwe_id="CWE-20",
        impact_description="Validator commission manipulation and delegator exploitation",
        exploitability="Medium",
        prevention_strategies=["Implement commission caps", "Add rate limiting", "Require cooldown periods"]
    ),
    SecurityRule(
        id="RP-026",
        name="AMM Liquidity Pool Manipulation",
        pattern=r'pool\.swap\([^)]*\)(?!.*minimum_liquidity|.*reserve_ratio)',
        severity="High",
        category="DeFi",
        description="AMM swap without liquidity and reserve ratio validation",
        fix_example="require!(pool.liquidity >= MIN_LIQUIDITY && reserve_ratio_valid, ErrorCode::InsufficientLiquidity);",
        cwe_id="CWE-682",
        impact_description="Liquidity pool manipulation and arbitrage exploitation",
        exploitability="High",
        prevention_strategies=["Validate minimum liquidity", "Check reserve ratios", "Implement swap limits"]
    ),
    SecurityRule(
        id="RP-027",
        name="Yield Farm Reward Calculation Overflow",
        pattern=r'rewards\s*=\s*stake\s*\*\s*rate(?!.*checked_mul)',
        severity="High",
        category="DeFi",
        description="Yield farming reward calculation without overflow protection",
        fix_example="let rewards = stake.checked_mul(rate).ok_or(ErrorCode::RewardOverflow)?;",
        cwe_id="CWE-190",
        impact_description="Reward calculation overflow leading to economic exploitation",
        exploitability="High",
        prevention_strategies=["Use checked arithmetic", "Implement reward caps", "Add overflow validation"]
    ),
    SecurityRule(
        id="RP-028",
        name="NFT Royalty Bypass",
        pattern=r'nft\.transfer\([^)]*\)(?!.*royalty_fee|.*creator_fee)',
        severity="Medium",
        category="NFT Security",
        description="NFT transfer without enforcing royalty payments",
        fix_example="require!(royalty_paid >= calculate_royalty(price), ErrorCode::RoyaltyNotPaid);",
        cwe_id="CWE-863",
        impact_description="Creator royalty bypass and revenue loss",
        exploitability="Medium",
        prevention_strategies=["Enforce royalty payments", "Validate creator fees", "Implement royalty standards"]
    ),
    SecurityRule(
        id="RP-029",
        name="Program Upgrade Authority Bypass",
        pattern=r'program\.upgrade\([^)]*\)(?!.*upgrade_authority)',
        severity="Critical",
        category="Program Security",
        description="Program upgrade without proper upgrade authority validation",
        fix_example="require!(program_data.upgrade_authority == Some(authority.key()), ErrorCode::InvalidUpgradeAuthority);",
        cwe_id="CWE-862",
        impact_description="Unauthorized program upgrades and malicious code injection",
        exploitability="High",
        prevention_strategies=["Validate upgrade authority", "Implement upgrade delays", "Use multi-sig for upgrades"]
    ),
    SecurityRule(
        id="RP-030",
        name="Vault Withdraw Authority Bypass",
        pattern=r'vault\.withdraw\([^)]*\)(?!.*withdraw_authority)',
        severity="Critical",
        category="Vault Security",
        description="Vault withdrawal without proper withdraw authority validation",
        fix_example="require!(vault.withdraw_authority == authority.key(), ErrorCode::InvalidWithdrawAuthority);",
        cwe_id="CWE-862",
        impact_description="Unauthorized vault withdrawals and fund drainage",
        exploitability="High",
        prevention_strategies=["Validate withdraw authority", "Implement withdrawal limits", "Add multi-sig requirements"]
    ),
    SecurityRule(
        id="RP-031",
        name="Lending Protocol Interest Rate Manipulation",
        pattern=r'interest_rate\s*=\s*calculate_rate\([^)]*\)(?!.*rate_cap|.*validation)',
        severity="High",
        category="DeFi",
        description="Interest rate calculation without manipulation protection",
        fix_example="require!(interest_rate <= MAX_INTEREST_RATE && rate_valid, ErrorCode::InvalidInterestRate);",
        cwe_id="CWE-682",
        impact_description="Interest rate manipulation and borrowing exploitation",
        exploitability="High",
        prevention_strategies=["Implement rate caps", "Add rate validation", "Use time-weighted averages"]
    ),
    SecurityRule(
        id="RP-032",
        name="DAO Proposal Quorum Bypass",
        pattern=r'proposal\.execute\([^)]*\)(?!.*quorum_met|.*voting_threshold)',
        severity="High",
        category="Governance",
        description="DAO proposal execution without sufficient quorum validation",
        fix_example="require!(votes >= quorum_threshold && voting_period_ended, ErrorCode::InsufficientQuorum);",
        cwe_id="CWE-863",
        impact_description="Governance bypass through insufficient voting validation",
        exploitability="Medium",
        prevention_strategies=["Validate voting quorum", "Check voting thresholds", "Implement voting delays"]
    ),
    SecurityRule(
        id="RP-033",
        name="Auction Bid Manipulation",
        pattern=r'auction\.place_bid\([^)]*\)(?!.*bid_increment|.*minimum_bid)',
        severity="Medium",
        category="Auction Security",
        description="Auction bid placement without proper increment and minimum validation",
        fix_example="require!(bid >= current_bid + min_increment && bid >= reserve_price, ErrorCode::InvalidBid);",
        cwe_id="CWE-20",
        impact_description="Auction manipulation and unfair bidding",
        exploitability="Medium",
        prevention_strategies=["Validate bid increments", "Check minimum bids", "Implement bid validation"]
    ),
    SecurityRule(
        id="RP-034",
        name="Insurance Pool Premium Calculation Error",
        pattern=r'premium\s*=\s*coverage\s*\/\s*\w+(?!.*risk_factor|.*checked_div)',
        severity="High",
        category="Insurance",
        description="Insurance premium calculation without risk factor validation",
        fix_example="let premium = coverage.checked_div(risk_adjusted_factor).ok_or(ErrorCode::PremiumCalculationError)?;",
        cwe_id="CWE-682",
        impact_description="Incorrect premium calculation and insurance exploitation",
        exploitability="Medium",
        prevention_strategies=["Include risk factors", "Use checked division", "Validate premium bounds"]
    ),
    SecurityRule(
        id="RP-035",
        name="Perpetual Futures Funding Rate Manipulation",
        pattern=r'funding_rate\s*=\s*\w+(?!.*time_weighted|.*manipulation_check)',
        severity="High",
        category="DeFi",
        description="Perpetual futures funding rate without manipulation protection",
        fix_example="require!(is_time_weighted_rate(funding_rate) && !manipulation_detected, ErrorCode::FundingRateManipulation);",
        cwe_id="CWE-682",
        impact_description="Funding rate manipulation and trading exploitation",
        exploitability="High",
        prevention_strategies=["Use time-weighted rates", "Add manipulation detection", "Implement rate bounds"]
    ),
    SecurityRule(
        id="RP-036",
        name="Identity Verification Bypass",
        pattern=r'identity\.verify\([^)]*\)(?!.*kyc_level|.*verification_proof)',
        severity="Medium",
        category="Identity",
        description="Identity verification without proper KYC level validation",
        fix_example="require!(identity.kyc_level >= required_level && proof_valid, ErrorCode::InsufficientVerification);",
        cwe_id="CWE-287",
        impact_description="Identity verification bypass and compliance violations",
        exploitability="Low",
        prevention_strategies=["Validate KYC levels", "Check verification proofs", "Implement compliance checks"]
    ),
    SecurityRule(
        id="RP-037",
        name="Escrow Release Condition Bypass",
        pattern=r'escrow\.release\([^)]*\)(?!.*conditions_met|.*dispute_resolved)',
        severity="High",
        category="Escrow Security",
        description="Escrow funds release without proper condition validation",
        fix_example="require!(all_conditions_met() && !dispute_active, ErrorCode::EscrowConditionsNotMet);",
        cwe_id="CWE-863",
        impact_description="Premature escrow release and fund loss",
        exploitability="Medium",
        prevention_strategies=["Validate release conditions", "Check dispute status", "Implement condition tracking"]
    ),
    SecurityRule(
        id="RP-038",
        name="Multi-Signature Threshold Bypass",
        pattern=r'multisig\.execute\([^)]*\)(?!.*signature_count|.*threshold_met)',
        severity="Critical",
        category="Multi-Sig Security",
        description="Multi-signature execution without proper threshold validation",
        fix_example="require!(valid_signatures >= threshold && signatures_verified, ErrorCode::InsufficientSignatures);",
        cwe_id="CWE-345",
        impact_description="Multi-sig bypass and unauthorized transaction execution",
        exploitability="High",
        prevention_strategies=["Validate signature count", "Check signature threshold", "Verify signature authenticity"]
    ),
    SecurityRule(
        id="RP-039",
        name="Derivative Position Liquidation Bypass",
        pattern=r'position\.liquidate\([^)]*\)(?!.*margin_ratio|.*liquidation_threshold)',
        severity="High",
        category="DeFi",
        description="Derivative position liquidation without proper margin validation",
        fix_example="require!(margin_ratio < liquidation_threshold && grace_period_expired, ErrorCode::PrematureLiquidation);",
        cwe_id="CWE-682",
        impact_description="Improper liquidation and trader exploitation",
        exploitability="High",
        prevention_strategies=["Validate margin ratios", "Check liquidation thresholds", "Implement grace periods"]
    ),
    SecurityRule(
        id="RP-040",
        name="Synthetic Asset Collateral Manipulation",
        pattern=r'synthetic\.mint\([^)]*\)(?!.*collateral_ratio|.*price_feed)',
        severity="Critical",
        category="Synthetic Assets",
        description="Synthetic asset minting without proper collateral validation",
        fix_example="require!(collateral_ratio >= MIN_RATIO && price_feed_valid, ErrorCode::InsufficientCollateral);",
        cwe_id="CWE-682",
        impact_description="Under-collateralized synthetic asset creation",
        exploitability="High",
        prevention_strategies=["Validate collateral ratios", "Check price feeds", "Implement overcollateralization"]
    ),
    SecurityRule(
        id="RP-041",
        name="Cross-Program Account Sharing Vulnerability",
        pattern=r'invoke_signed\([^)]*\)(?!.*account_ownership_check)',
        severity="High",
        category="Cross Program",
        description="Cross-program invocation with signed accounts without ownership validation",
        fix_example="require!(validate_account_ownership(accounts) && authorized_program, ErrorCode::UnauthorizedCPI);",
        cwe_id="CWE-863",
        impact_description="Account sharing vulnerabilities in CPI calls",
        exploitability="High",
        prevention_strategies=["Validate account ownership", "Check program authorization", "Implement CPI guards"]
    ),
    SecurityRule(
        id="RP-042",
        name="Token Burn Authority Bypass",
        pattern=r'token\.burn\([^)]*\)(?!.*burn_authority)',
        severity="Medium",
        category="Token Security",
        description="Token burning without proper burn authority validation",
        fix_example="require!(token_account.owner == burn_authority.key(), ErrorCode::InvalidBurnAuthority);",
        cwe_id="CWE-862",
        impact_description="Unauthorized token burning",
        exploitability="Medium",
        prevention_strategies=["Validate burn authority", "Check account ownership", "Implement burn limits"]
    ),
    SecurityRule(
        id="RP-043",
        name="Vesting Schedule Manipulation",
        pattern=r'vesting\.claim\([^)]*\)(?!.*schedule_check|.*cliff_period)',
        severity="Medium",
        category="Token Vesting",
        description="Token vesting claim without proper schedule validation",
        fix_example="require!(current_time >= cliff_time && vested_amount_valid, ErrorCode::VestingNotReady);",
        cwe_id="CWE-367",
        impact_description="Premature token vesting and economic manipulation",
        exploitability="Medium",
        prevention_strategies=["Validate vesting schedules", "Check cliff periods", "Implement vesting calculations"]
    ),
    SecurityRule(
        id="RP-044",
        name="Liquidity Mining Reward Pool Drain",
        pattern=r'rewards\.claim\([^)]*\)(?!.*pool_balance|.*reward_rate)',
        severity="High",
        category="DeFi",
        description="Liquidity mining reward claim without pool balance validation",
        fix_example="require!(pool_balance >= reward_amount && reward_rate_valid, ErrorCode::InsufficientRewardPool);",
        cwe_id="CWE-682",
        impact_description="Reward pool drainage and liquidity mining exploitation",
        exploitability="High",
        prevention_strategies=["Validate pool balances", "Check reward rates", "Implement reward caps"]
    ),
    SecurityRule(
        id="RP-045",
        name="Dynamic Fee Calculation Manipulation",
        pattern=r'fee\s*=\s*calculate_dynamic_fee\([^)]*\)(?!.*fee_cap|.*manipulation_check)',
        severity="Medium",
        category="Fee Management",
        description="Dynamic fee calculation without manipulation protection",
        fix_example="require!(fee <= MAX_FEE && !fee_manipulation_detected, ErrorCode::InvalidFee);",
        cwe_id="CWE-682",
        impact_description="Fee manipulation and economic exploitation",
        exploitability="Medium",
        prevention_strategies=["Implement fee caps", "Add manipulation detection", "Use fee smoothing"]
    ),
    SecurityRule(
        id="RP-046",
        name="Margin Trading Position Size Bypass",
        pattern=r'position\.open\([^)]*\)(?!.*position_limit|.*margin_requirement)',
        severity="High",
        category="Margin Trading",
        description="Margin trading position opening without size and margin validation",
        fix_example="require!(position_size <= max_position && margin >= required_margin, ErrorCode::InvalidPosition);",
        cwe_id="CWE-20",
        impact_description="Excessive leverage and margin trading risks",
        exploitability="High",
        prevention_strategies=["Validate position sizes", "Check margin requirements", "Implement leverage limits"]
    ),
    SecurityRule(
        id="RP-047",
        name="Oracle Price Deviation Attack",
        pattern=r'price\s*=\s*oracle\.get_price\([^)]*\)(?!.*deviation_check|.*circuit_breaker)',
        severity="High",
        category="Oracle",
        description="Oracle price usage without deviation and circuit breaker validation",
        fix_example="require!(price_deviation < MAX_DEVIATION && !circuit_breaker_triggered, ErrorCode::PriceDeviation);",
        cwe_id="CWE-20",
        impact_description="Oracle price manipulation and market disruption",
        exploitability="High",
        prevention_strategies=["Check price deviations", "Implement circuit breakers", "Use multiple oracle sources"]
    ),
    SecurityRule(
        id="RP-048",
        name="Automated Market Maker K-Value Manipulation",
        pattern=r'k_value\s*=\s*x\s*\*\s*y(?!.*k_validation|.*slippage_protection)',
        severity="High",
        category="AMM Security",
        description="AMM K-value calculation without manipulation protection",
        fix_example="require!(k_value >= previous_k && slippage_protected, ErrorCode::KValueManipulation);",
        cwe_id="CWE-682",
        impact_description="AMM manipulation and liquidity exploitation",
        exploitability="High",
        prevention_strategies=["Validate K-value consistency", "Add slippage protection", "Implement invariant checks"]
    ),
    SecurityRule(
        id="RP-049",
        name="Credit Score Calculation Bypass",
        pattern=r'credit_score\s*=\s*calculate_score\([^)]*\)(?!.*historical_data|.*verification)',
        severity="Medium",
        category="Credit Systems",
        description="Credit score calculation without historical data validation",
        fix_example="require!(historical_data_sufficient && data_verified, ErrorCode::InsufficientCreditData);",
        cwe_id="CWE-20",
        impact_description="Credit score manipulation and lending risks",
        exploitability="Medium",
        prevention_strategies=["Validate historical data", "Verify data sources", "Implement score bounds"]
    ),
    SecurityRule(
        id="RP-050",
        name="Prediction Market Resolution Manipulation",
        pattern=r'market\.resolve\([^)]*\)(?!.*oracle_consensus|.*dispute_period)',
        severity="High",
        category="Prediction Markets",
        description="Prediction market resolution without proper oracle consensus",
        fix_example="require!(oracle_consensus_reached && dispute_period_expired, ErrorCode::PrematureResolution);",
        cwe_id="CWE-345",
        impact_description="Market manipulation and unfair resolution",
        exploitability="Medium",
        prevention_strategies=["Require oracle consensus", "Implement dispute periods", "Add resolution validation"]
    ),
    SecurityRule(
        id="RP-051",
        name="Social Token Reputation Manipulation",
        pattern=r'reputation\s*\+=\s*\w+(?!.*reputation_cap|.*activity_validation)',
        severity="Medium",
        category="Social Tokens",
        description="Social token reputation increase without activity validation",
        fix_example="require!(activity_verified && reputation <= MAX_REPUTATION, ErrorCode::InvalidReputationIncrease);",
        cwe_id="CWE-20",
        impact_description="Reputation manipulation and social token exploitation",
        exploitability="Low",
        prevention_strategies=["Validate activities", "Implement reputation caps", "Add sybil protection"]
    ),
    SecurityRule(
        id="RP-052",
        name="Decentralized Exchange Order Book Manipulation",
        pattern=r'order\.fill\([^)]*\)(?!.*price_validation|.*order_matching)',
        severity="High",
        category="DEX Security",
        description="DEX order filling without proper price and matching validation",
        fix_example="require!(price_within_bounds && order_matching_valid, ErrorCode::InvalidOrderFill);",
        cwe_id="CWE-682",
        impact_description="Order book manipulation and price distortion",
        exploitability="High",
        prevention_strategies=["Validate order prices", "Check order matching", "Implement price bounds"]
    ),
    SecurityRule(
        id="RP-053",
        name="Tokenized Real Estate Valuation Bypass",
        pattern=r'property_value\s*=\s*\w+(?!.*appraisal_verification|.*market_validation)',
        severity="Medium",
        category="Real Estate Tokens",
        description="Tokenized real estate valuation without proper appraisal verification",
        fix_example="require!(appraisal_verified && market_value_valid, ErrorCode::InvalidPropertyValuation);",
        cwe_id="CWE-20",
        impact_description="Property valuation manipulation and investment risks",
        exploitability="Low",
        prevention_strategies=["Verify appraisals", "Validate market values", "Use multiple valuation sources"]
    ),
    SecurityRule(
        id="RP-054",
        name="Cross-Chain Message Verification Failure",
        pattern=r'message\.verify\([^)]*\)(?!.*merkle_proof|.*validator_signatures)',
        severity="Critical",
        category="Cross-Chain",
        description="Cross-chain message verification without proper cryptographic proofs",
        fix_example="require!(merkle_proof_valid && validator_signatures_verified, ErrorCode::InvalidCrossChainMessage);",
        cwe_id="CWE-345",
        impact_description="Cross-chain message manipulation and bridge exploits",
        exploitability="High",
        prevention_strategies=["Validate merkle proofs", "Verify validator signatures", "Implement consensus checks"]
    ),
    SecurityRule(
        id="RP-055",
        name="Algorithmic Stablecoin Peg Manipulation",
        pattern=r'peg_adjustment\s*=\s*\w+(?!.*price_oracle|.*stability_mechanism)',
        severity="High",
        category="Algorithmic Stablecoins",
        description="Algorithmic stablecoin peg adjustment without proper stability mechanisms",
        fix_example="require!(price_oracle_valid && stability_mechanism_active, ErrorCode::PegManipulation);",
        cwe_id="CWE-682",
        impact_description="Stablecoin peg manipulation and market instability",
        exploitability="High",
        prevention_strategies=["Use reliable price oracles", "Implement stability mechanisms", "Add peg protection"]
    ),
    SecurityRule(
        id="RP-056",
        name="Yield Optimization Strategy Manipulation",
        pattern=r'yield_strategy\.execute\([^)]*\)(?!.*risk_assessment|.*strategy_validation)',
        severity="Medium",
        category="Yield Optimization",
        description="Yield optimization strategy execution without risk assessment",
        fix_example="require!(risk_within_bounds && strategy_validated, ErrorCode::InvalidYieldStrategy);",
        cwe_id="CWE-20",
        impact_description="Yield strategy manipulation and investment risks",
        exploitability="Medium",
        prevention_strategies=["Assess strategy risks", "Validate strategies", "Implement risk limits"]
    ),
    SecurityRule(
        id="RP-057",
        name="Decentralized Identity Credential Forgery",
        pattern=r'credential\.issue\([^)]*\)(?!.*issuer_verification|.*credential_schema)',
        severity="Medium",
        category="Decentralized Identity",
        description="Decentralized identity credential issuance without proper verification",
        fix_example="require!(issuer_authorized && credential_schema_valid, ErrorCode::InvalidCredential);",
        cwe_id="CWE-287",
        impact_description="Identity credential forgery and authentication bypass",
        exploitability="Low",
        prevention_strategies=["Verify issuers", "Validate credential schemas", "Implement credential checks"]
    ),
    SecurityRule(
        id="RP-058",
        name="Gaming Asset Transfer Manipulation",
        pattern=r'game_asset\.transfer\([^)]*\)(?!.*ownership_proof|.*transfer_rules)',
        severity="Medium",
        category="Gaming Assets",
        description="Gaming asset transfer without proper ownership and rule validation",
        fix_example="require!(ownership_proven && transfer_rules_met, ErrorCode::InvalidAssetTransfer);",
        cwe_id="CWE-863",
        impact_description="Gaming asset manipulation and unfair advantages",
        exploitability="Low",
        prevention_strategies=["Prove asset ownership", "Validate transfer rules", "Implement game mechanics"]
    ),
    SecurityRule(
        id="RP-059",
        name="Carbon Credit Verification Bypass",
        pattern=r'carbon_credit\.mint\([^)]*\)(?!.*environmental_proof|.*third_party_verification)',
        severity="Medium",
        category="Environmental Tokens",
        description="Carbon credit minting without proper environmental verification",
        fix_example="require!(environmental_impact_proven && third_party_verified, ErrorCode::InvalidCarbonCredit);",
        cwe_id="CWE-20",
        impact_description="Carbon credit fraud and environmental impact misrepresentation",
        exploitability="Low",
        prevention_strategies=["Verify environmental impact", "Require third-party verification", "Implement auditing"]
    ),
    SecurityRule(
        id="RP-060",
        name="Decentralized Storage Payment Channel Manipulation",
        pattern=r'storage_payment\.process\([^)]*\)(?!.*storage_proof|.*payment_validation)',
        severity="Medium",
        category="Decentralized Storage",
        description="Decentralized storage payment processing without storage proof validation",
        fix_example="require!(storage_proof_valid && payment_amount_correct, ErrorCode::InvalidStoragePayment);",
        cwe_id="CWE-682",
        impact_description="Storage payment manipulation and service exploitation",
        exploitability="Medium",
        prevention_strategies=["Validate storage proofs", "Verify payment amounts", "Implement proof-of-storage"]
    ),
]

# Enhanced vulnerability correlation system
class VulnerabilityCorrelator:
    CORRELATION_RULES = [
        {
            "patterns": ["RP-001", "RP-003"],
            "severity_boost": "CRITICAL_AMPLIFIED", 
            "description": "Complete access control bypass - multiple authorization failures",
            "impact_multiplier": 2.0
        },
        {
            "patterns": ["RP-002", "RP-006"],
            "severity_boost": "CRITICAL_FINANCIAL",
            "description": "Financial manipulation vulnerability - overflow + slippage",
            "impact_multiplier": 1.8
        },
        {
            "patterns": ["RP-004", "RP-009"],
            "severity_boost": "HIGH_AMPLIFIED",
            "description": "Account manipulation attack surface",
            "impact_multiplier": 1.5
        },
        {
            "patterns": ["RP-005", "RP-014"],
            "severity_boost": "CRITICAL_DEFI",
            "description": "Oracle manipulation with liquidation risk",
            "impact_multiplier": 2.2
        },
        {
            "patterns": ["RP-021", "RP-022"],
            "severity_boost": "CRITICAL_TOKEN",
            "description": "Token authority bypass vulnerabilities",
            "impact_multiplier": 2.1
        },
        {
            "patterns": ["RP-023", "RP-054"],
            "severity_boost": "CRITICAL_BRIDGE",
            "description": "Cross-chain bridge validation failures",
            "impact_multiplier": 2.5
        },
        {
            "patterns": ["RP-026", "RP-048"],
            "severity_boost": "HIGH_AMM",
            "description": "AMM manipulation vulnerabilities",
            "impact_multiplier": 1.9
        },
        {
            "patterns": ["RP-029", "RP-038"],
            "severity_boost": "CRITICAL_GOVERNANCE",
            "description": "Governance and upgrade authority bypass",
            "impact_multiplier": 2.3
        },
        {
            "patterns": ["RP-031", "RP-035"],
            "severity_boost": "HIGH_RATE_MANIPULATION",
            "description": "Interest and funding rate manipulation",
            "impact_multiplier": 1.7
        },
        {
            "patterns": ["RP-040", "RP-055"],
            "severity_boost": "CRITICAL_STABLECOIN",
            "description": "Synthetic asset and stablecoin manipulation",
            "impact_multiplier": 2.0
        }
    ]
    
    @staticmethod
    def correlate_vulnerabilities(vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        found_patterns = {vuln.rule_id for vuln in vulnerabilities}
        correlations = []
        
        for rule in VulnerabilityCorrelator.CORRELATION_RULES:
            if all(pattern in found_patterns for pattern in rule["patterns"]):
                correlations.append(rule)
        
        return {
            "correlations": correlations,
            "amplified_severity": len(correlations) > 0,
            "risk_multiplier": sum(c["impact_multiplier"] for c in correlations)
        }

async def analyze_rust_code(file_content: str, file_path: str) -> List[Vulnerability]:
    """RustProof analysis with advanced pattern matching and context awareness"""
    vulnerabilities = []
    lines = file_content.split('\n')
    
    for rule in RUSTPROOF_SECURITY_RULES:
        pattern = re.compile(rule.pattern, re.MULTILINE | re.DOTALL)
        matches = pattern.finditer(file_content)
        
        for match in matches:
            # Find the line number
            line_number = file_content[:match.start()].count('\n') + 1
            
            # Get enhanced code snippet (5 lines context)
            start_line = max(0, line_number - 3)
            end_line = min(len(lines), line_number + 3)
            code_snippet = '\n'.join(lines[start_line:end_line])
            
            # Calculate impact score based on severity and context
            impact_score = {
                "Critical": 100,
                "High": 75,
                "Medium": 50,
                "Low": 25
            }.get(rule.severity, 25)
            
            # Enhanced fix suggestion with context
            fix_suggestion = f"{rule.description}. {rule.fix_example}"
            if rule.real_world_example:
                fix_suggestion += f"\n\nReal-world context: {rule.real_world_example}"
            
            vulnerability = Vulnerability(
                rule_id=rule.id,
                severity=rule.severity,
                category=rule.category,
                file_path=file_path,
                line_number=line_number,
                code_snippet=code_snippet,
                description=rule.description,
                fix_suggestion=fix_suggestion,
                fix_example=rule.fix_example,
                cwe_id=rule.cwe_id,
                impact_score=impact_score,
                exploitability=rule.exploitability,
                real_world_example=rule.real_world_example
            )
            vulnerabilities.append(vulnerability)
    
    return vulnerabilities

def calculate_enhanced_security_score(vulnerabilities: List[Vulnerability], metrics: SecurityMetrics) -> Dict[str, Any]:
    """Enhanced security scoring with multiple factors"""
    if not vulnerabilities:
        base_score = 95  # Not perfect due to potential unknown issues
    else:
        # Severity-based deduction
        severity_weights = {
            "Critical": 30,
            "High": 18, 
            "Medium": 10,
            "Low": 4
        }
        
        deduction = sum(severity_weights.get(vuln.severity, 5) for vuln in vulnerabilities)
        
        # Apply correlation multiplier
        correlation_data = VulnerabilityCorrelator.correlate_vulnerabilities(vulnerabilities)
        if correlation_data["amplified_severity"]:
            deduction *= correlation_data["risk_multiplier"]
        
        base_score = max(0, 100 - deduction)
    
    # Factor in complexity and attack surface
    complexity_penalty = min(20, metrics.complexity_score // 100)
    attack_surface_penalty = min(15, metrics.attack_surface_score // 150)
    
    final_score = max(0, base_score - complexity_penalty - attack_surface_penalty)
    
    # Risk assessment
    if final_score >= 80:
        risk_level = "Low"
    elif final_score >= 60:
        risk_level = "Medium" 
    elif final_score >= 40:
        risk_level = "High"
    else:
        risk_level = "Critical"
    
    return {
        "score": int(final_score),
        "risk_level": risk_level,
        "correlation_data": correlation_data,
        "penalties": {
            "complexity": complexity_penalty,
            "attack_surface": attack_surface_penalty
        }
    }

def generate_compliance_report(vulnerabilities: List[Vulnerability]) -> ComplianceReport:
    """Generate compliance scoring for various frameworks"""
    report = ComplianceReport()
    
    # SOC 2 scoring
    access_control_issues = len([v for v in vulnerabilities if v.category == "Access Control"])
    report.soc2_score = max(0, 100 - (access_control_issues * 15))
    
    # NIST scoring
    security_issues = len([v for v in vulnerabilities if v.severity in ["Critical", "High"]])
    report.nist_score = max(0, 100 - (security_issues * 12))
    
    # OWASP scoring
    smart_contract_issues = len([v for v in vulnerabilities if v.cwe_id])
    report.owasp_score = max(0, 100 - (smart_contract_issues * 8))
    
    # Missing controls identification
    if access_control_issues > 0:
        report.missing_controls.append("Proper access control implementation")
    if any(v.category == "Oracle" for v in vulnerabilities):
        report.missing_controls.append("Oracle validation controls")
    if any(v.category == "DeFi" for v in vulnerabilities):
        report.missing_controls.append("DeFi security controls")
    
    return report

def calculate_remediation_metrics(vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
    """Calculate remediation priorities"""
    # Priority mapping
    priority_order = []
    critical_vulns = [v for v in vulnerabilities if v.severity == "Critical"]
    high_vulns = [v for v in vulnerabilities if v.severity == "High"]
    
    # Prioritize by impact and exploitability
    for vuln in sorted(critical_vulns, key=lambda x: x.impact_score, reverse=True):
        priority_order.append(f"{vuln.rule_id}: {vuln.description}")
    
    for vuln in sorted(high_vulns, key=lambda x: x.impact_score, reverse=True):
        priority_order.append(f"{vuln.rule_id}: {vuln.description}")
    
    return {
        "priority_order": priority_order[:10],  # Top 10 priorities
        "critical_count": len(critical_vulns),
        "high_count": len(high_vulns)
    }

def generate_professional_pdf_report(scan_data: dict, filename: str) -> str:
    """Generate a professional PDF report for RustProof scan results"""
    
    # Create document
    doc = SimpleDocTemplate(filename, pagesize=A4)
    
    # Get styles
    styles = getSampleStyleSheet()
    
    # Custom styles for RustProof branding
    title_style = ParagraphStyle(
        'RustProofTitle',
        parent=styles['Title'],
        fontSize=28,
        textColor=colors.HexColor('#D2691E'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    subtitle_style = ParagraphStyle(
        'RustProofSubtitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#FF6B35'),
        spaceAfter=12,
        spaceBefore=20
    )
    
    heading_style = ParagraphStyle(
        'RustProofHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#D2691E'),
        spaceAfter=10,
        spaceBefore=15
    )
    
    body_style = ParagraphStyle(
        'RustProofBody',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=6,
        textColor=colors.black
    )
    
    # Build document content
    story = []
    
    # Header
    story.append(Paragraph("🛡️ RustProof", title_style))
    story.append(Paragraph("Professional Solana Security Analysis Report", subtitle_style))
    story.append(Spacer(1, 20))
    
    # Scan Summary
    story.append(Paragraph("📋 Scan Summary", heading_style))
    
    summary_data = [
        ['File Name', scan_data.get('file_name', 'Unknown')],
        ['Scan Date', scan_data.get('created_at', '').split('T')[0] if scan_data.get('created_at') else 'Unknown'],
        ['Lines Analyzed', str(scan_data.get('security_metrics', {}).get('total_lines_analyzed', 0))],
        ['Security Score', f"{scan_data.get('security_score', 0)}/100"],
        ['Risk Level', scan_data.get('risk_assessment', 'Unknown')],
        ['Total Vulnerabilities', str(scan_data.get('total_vulnerabilities', 0))]
    ]
    
    summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F5F5F5')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#D2691E')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#CCCCCC')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # Vulnerability Breakdown
    story.append(Paragraph("🔍 Vulnerability Breakdown", heading_style))
    
    vuln_breakdown = [
        ['Severity', 'Count', 'Description'],
        ['Critical', str(scan_data.get('critical_count', 0)), 'Immediate attention required'],
        ['High', str(scan_data.get('high_count', 0)), 'Should be fixed soon'],
        ['Medium', str(scan_data.get('medium_count', 0)), 'Fix when convenient'],
        ['Low', str(scan_data.get('low_count', 0)), 'Minor improvements']
    ]
    
    vuln_table = Table(vuln_breakdown, colWidths=[1.5*inch, 1*inch, 3*inch])
    vuln_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#D2691E')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#CCCCCC')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(vuln_table)
    story.append(Spacer(1, 20))
    
    # Security Metrics
    metrics = scan_data.get('security_metrics', {})
    if metrics:
        story.append(Paragraph("📊 Security Analysis", heading_style))
        
        metrics_data = [
            ['Metric', 'Score', 'Assessment'],
            ['Complexity Score', str(metrics.get('complexity_score', 0)), 'Code complexity level'],
            ['Attack Surface', str(metrics.get('attack_surface_score', 0)), 'Exposed attack vectors'],
            ['DeFi Risk Score', str(metrics.get('defi_risk_score', 0)), 'DeFi-specific vulnerabilities'],
            ['Business Logic Score', str(metrics.get('business_logic_score', 0)), 'Business logic complexity']
        ]
        
        metrics_table = Table(metrics_data, colWidths=[2*inch, 1*inch, 2.5*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4682B4')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#CCCCCC')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(metrics_table)
        story.append(Spacer(1, 20))
    
    # Compliance Assessment
    compliance = scan_data.get('compliance_report', {})
    if compliance:
        story.append(Paragraph("📋 Compliance Assessment", heading_style))
        
        compliance_data = [
            ['Framework', 'Score', 'Status'],
            ['SOC 2 Compliance', f"{compliance.get('soc2_score', 0)}%", 'Access controls and security'],
            ['NIST Framework', f"{compliance.get('nist_score', 0)}%", 'Cybersecurity framework'],
            ['OWASP Smart Contract', f"{compliance.get('owasp_score', 0)}%", 'Smart contract security']
        ]
        
        compliance_table = Table(compliance_data, colWidths=[2*inch, 1*inch, 2.5*inch])
        compliance_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#10B981')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#CCCCCC')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(compliance_table)
        story.append(Spacer(1, 20))
    
    # Detailed Findings (if vulnerabilities exist)
    vulnerabilities = scan_data.get('vulnerabilities', [])
    if vulnerabilities:
        story.append(PageBreak())
        story.append(Paragraph("📊 Detailed Vulnerability Findings", heading_style))
        story.append(Spacer(1, 10))
        
        for i, vuln in enumerate(vulnerabilities[:10], 1):  # Limit to first 10 for PDF space
            story.append(Paragraph(f"Finding #{i}: {vuln.get('rule_id', 'Unknown')}", subtitle_style))
            
            vuln_details = [
                ['Field', 'Value'],
                ['Severity', vuln.get('severity', 'Unknown')],
                ['Category', vuln.get('category', 'Unknown')],
                ['Line Number', str(vuln.get('line_number', 'Unknown'))],
                ['CWE ID', vuln.get('cwe_id', 'N/A')],
                ['Impact Score', f"{vuln.get('impact_score', 0)}/100"],
                ['Exploitability', vuln.get('exploitability', 'Unknown')]
            ]
            
            vuln_table = Table(vuln_details, colWidths=[1.5*inch, 4*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F5F5F5')),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#D2691E')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#CCCCCC')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(vuln_table)
            
            # Description
            story.append(Paragraph(f"<b>Description:</b> {vuln.get('description', 'No description available')}", body_style))
            
            # Code snippet (truncated for PDF)
            code_snippet = vuln.get('code_snippet', '')
            if code_snippet:
                truncated_code = code_snippet[:200] + "..." if len(code_snippet) > 200 else code_snippet
                story.append(Paragraph(f"<b>Vulnerable Code:</b>", body_style))
                story.append(Paragraph(f"<font name='Courier'>{truncated_code}</font>", body_style))
            
            story.append(Spacer(1, 15))
        
        if len(vulnerabilities) > 10:
            story.append(Paragraph(f"<i>... and {len(vulnerabilities) - 10} more vulnerabilities. Full details available in JSON export.</i>", body_style))
    
    # Remediation Roadmap
    remediation = scan_data.get('remediation_priority', [])
    if remediation:
        story.append(PageBreak())
        story.append(Paragraph("🔧 Remediation Roadmap", heading_style))
        story.append(Paragraph("Priority-ordered list of security issues to address:", body_style))
        story.append(Spacer(1, 10))
        
        for i, item in enumerate(remediation[:10], 1):  # Top 10 priorities
            story.append(Paragraph(f"{i}. {item}", body_style))
        
        if len(remediation) > 10:
            story.append(Paragraph(f"... and {len(remediation) - 10} more items", body_style))
    
    # Footer
    story.append(PageBreak())
    story.append(Spacer(1, 50))
    story.append(Paragraph("Generated by RustProof Professional Security Scanner", 
                          ParagraphStyle('Footer', parent=styles['Normal'], 
                                       fontSize=10, textColor=colors.HexColor('#666666'), 
                                       alignment=TA_CENTER)))
    story.append(Paragraph("Professional Solana Smart Contract Security Analysis", 
                          ParagraphStyle('FooterCredit', parent=styles['Normal'], 
                                       fontSize=9, textColor=colors.HexColor('#666666'), 
                                       alignment=TA_CENTER)))
    story.append(Paragraph("© 2025 RustProof Security Platform", 
                          ParagraphStyle('FooterLink', parent=styles['Normal'], 
                                       fontSize=9, textColor=colors.HexColor('#D2691E'), 
                                       alignment=TA_CENTER)))
    
    # Build PDF
    doc.build(story)
    
    return filename

@api_router.post("/scan", response_model=ScanResult)
async def start_scan(file: UploadFile = File(...)):
    """RustProof security scan with professional analytics"""
    if not file.filename.endswith(('.rs', '.rust')):
        raise HTTPException(status_code=400, detail="Only Rust files (.rs) are supported")
    
    # Create scan record with session tracking
    session_id = str(uuid.uuid4())
    scan = ScanResult(
        status="pending",
        file_count=1,
        session_id=session_id,
        file_name=file.filename
    )
    
    # Store in database
    await db.scans.insert_one(scan.dict())
    
    # Read file content
    file_content = await file.read()
    file_content = file_content.decode('utf-8')
    
    try:
        # Update status to scanning
        scan.status = "scanning"
        await db.scans.update_one({"id": scan.id}, {"$set": {"status": "scanning"}})
        
        # Enhanced analysis
        vulnerabilities = await analyze_rust_code(file_content, file.filename)
        
        # Calculate metrics
        lines_analyzed = len(file_content.split('\n'))
        complexity = len(re.findall(r'fn\s+\w+', file_content))
        attack_surface = len(re.findall(r'pub\s+fn', file_content))
        
        metrics = SecurityMetrics(
            total_lines_analyzed=lines_analyzed,
            complexity_score=complexity * 10,
            attack_surface_score=attack_surface * 15,
            business_logic_score=len(re.findall(r'transfer|mint|burn', file_content, re.IGNORECASE)) * 20,
            defi_risk_score=len(re.findall(r'swap|liquidity|oracle|price', file_content, re.IGNORECASE)) * 25
        )
        
        # Enhanced security scoring
        scoring_result = calculate_enhanced_security_score(vulnerabilities, metrics)
        
        # Generate compliance report
        compliance_report = generate_compliance_report(vulnerabilities)
        
        # Calculate remediation metrics
        remediation = calculate_remediation_metrics(vulnerabilities)
        
        # Count vulnerabilities by severity
        critical_count = sum(1 for v in vulnerabilities if v.severity == "Critical")
        high_count = sum(1 for v in vulnerabilities if v.severity == "High")
        medium_count = sum(1 for v in vulnerabilities if v.severity == "Medium")
        low_count = sum(1 for v in vulnerabilities if v.severity == "Low")
        
        # Update scan with all results
        scan.status = "completed"
        scan.vulnerabilities = vulnerabilities
        scan.total_vulnerabilities = len(vulnerabilities)
        scan.critical_count = critical_count
        scan.high_count = high_count
        scan.medium_count = medium_count
        scan.low_count = low_count
        scan.security_score = scoring_result["score"]
        scan.security_metrics = metrics
        scan.compliance_report = compliance_report
        scan.risk_assessment = scoring_result["risk_level"]
        scan.remediation_priority = remediation["priority_order"]
        
        # Store final results
        await db.scans.update_one(
            {"id": scan.id}, 
            {"$set": scan.dict()}
        )
        
        return scan
        
    except Exception as e:
        # Handle errors
        scan.status = "failed"
        await db.scans.update_one(
            {"id": scan.id}, 
            {"$set": {"status": "failed"}}
        )
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@api_router.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan_results(scan_id: str):
    """Get scan results by ID"""
    scan_data = await db.scans.find_one({"id": scan_id})
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return ScanResult(**scan_data)

@api_router.get("/scans/session/{session_id}", response_model=List[ScanResult])
async def get_session_scans(session_id: str):
    """Get scans for specific session only"""
    scans = await db.scans.find({"session_id": session_id}).sort("created_at", -1).to_list(100)
    return [ScanResult(**scan) for scan in scans]

@api_router.get("/rules", response_model=List[SecurityRule])
async def get_security_rules():
    """Get all RustProof security rules"""
    return RUSTPROOF_SECURITY_RULES

@api_router.get("/analytics/platform")
async def get_platform_analytics():
    """Get comprehensive platform analytics"""
    scans = await db.scans.find().to_list(1000)
    
    if not scans:
        return {
            "total_scans": 0,
            "average_security_score": 0,
            "total_vulnerabilities_found": 0,
            "rule_types": len(set(rule.category for rule in RUSTPROOF_SECURITY_RULES))
        }
    
    # Calculate aggregate metrics
    total_scans = len(scans)
    avg_security_score = sum(scan.get("security_score", 0) for scan in scans) / total_scans
    total_vulnerabilities = sum(scan.get("total_vulnerabilities", 0) for scan in scans)
    
    # Count unique rule categories
    rule_categories = set(rule.category for rule in RUSTPROOF_SECURITY_RULES)
    
    return {
        "total_scans": total_scans,
        "average_security_score": round(avg_security_score, 1),
        "total_vulnerabilities_found": total_vulnerabilities,
        "rule_types": len(rule_categories)
    }

@api_router.post("/export/pdf/{scan_id}")
async def export_scan_pdf(scan_id: str):
    """Export scan results as professional PDF report"""
    scan_data = await db.scans.find_one({"id": scan_id})
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        # Create temporary file
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_file:
            pdf_path = tmp_file.name
        
        # Create document
        doc = SimpleDocTemplate(pdf_path, pagesize=A4)
        styles = getSampleStyleSheet()
        
        # Custom styles for RustProof branding
        title_style = ParagraphStyle(
            'RustProofTitle',
            parent=styles['Title'],
            fontSize=24,
            textColor=colors.HexColor('#D2691E'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'RustProofHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#D2691E'),
            spaceAfter=10,
            spaceBefore=15
        )
        
        # Build document content
        story = []
        
        # Header
        story.append(Paragraph("RustProof Security Analysis Report", title_style))
        story.append(Spacer(1, 20))
        
        # Scan Summary
        story.append(Paragraph("Scan Summary", heading_style))
        
        summary_data = [
            ['File Name', scan_data.get('file_name', 'Unknown')],
            ['Scan Date', str(scan_data.get('created_at', ''))[:10]],
            ['Security Score', f"{scan_data.get('security_score', 0)}/100"],
            ['Risk Level', scan_data.get('risk_assessment', 'Unknown')],
            ['Total Vulnerabilities', str(scan_data.get('total_vulnerabilities', 0))]
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F5F5F5')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#D2691E')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#CCCCCC')),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Vulnerability Breakdown
        story.append(Paragraph("Vulnerability Breakdown", heading_style))
        
        vuln_breakdown = [
            ['Severity', 'Count'],
            ['Critical', str(scan_data.get('critical_count', 0))],
            ['High', str(scan_data.get('high_count', 0))],
            ['Medium', str(scan_data.get('medium_count', 0))],
            ['Low', str(scan_data.get('low_count', 0))]
        ]
        
        vuln_table = Table(vuln_breakdown, colWidths=[2*inch, 1*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#D2691E')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#CCCCCC')),
        ]))
        story.append(vuln_table)
        story.append(Spacer(1, 20))
        
        # Footer
        story.append(Spacer(1, 50))
        story.append(Paragraph("Generated by RustProof Professional Edition", 
                              ParagraphStyle('Footer', parent=styles['Normal'], 
                                           fontSize=10, textColor=colors.HexColor('#666666'), 
                                           alignment=TA_CENTER)))
        story.append(Paragraph("Developed with love by Akinator", 
                              ParagraphStyle('FooterCredit', parent=styles['Normal'], 
                                           fontSize=9, textColor=colors.HexColor('#666666'), 
                                           alignment=TA_CENTER)))
        
        # Build PDF
        doc.build(story)
        
        # Return file
        filename = f"RustProof_Security_Report_{scan_id[:8]}.pdf"
        return FileResponse(
            path=pdf_path,
            filename=filename,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        # Clean up temp file on error
        if 'pdf_path' in locals() and os.path.exists(pdf_path):
            os.unlink(pdf_path)
        logger.error(f"PDF generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")
    finally:
        # Schedule cleanup (file will be deleted after response is sent)
        def cleanup():
            try:
                if 'pdf_path' in locals() and os.path.exists(pdf_path):
                    os.unlink(pdf_path)
            except:
                pass
        
        # Clean up after a delay to ensure file is sent
        import threading
        threading.Timer(10.0, cleanup).start()
@api_router.post("/export/json/{scan_id}")
async def export_scan_json(scan_id: str):
    """Export scan results as JSON"""
    scan_data = await db.scans.find_one({"id": scan_id})
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Prepare JSON export with proper serialization
    export_data = {
        "metadata": {
            "tool": "RustProof",
            "version": "1.0",
            "scan_date": scan_data.get("created_at").isoformat() if scan_data.get("created_at") else None,
            "filename": scan_data.get("file_name", "unknown"),
            "scan_id": scan_id
        },
        "summary": {
            "lines_analyzed": scan_data.get("security_metrics", {}).get("total_lines_analyzed", 0),
            "security_score": scan_data.get("security_score", 0),
            "vulnerability_count": scan_data.get("total_vulnerabilities", 0),
            "risk_level": scan_data.get("risk_assessment", "Unknown")
        },
        "vulnerabilities": scan_data.get("vulnerabilities", []),
        "compliance": scan_data.get("compliance_report", {}),
        "analytics": scan_data.get("security_metrics", {}),
        "remediation": scan_data.get("remediation_priority", [])
    }
    
    return JSONResponse(
        content=export_data,
        headers={
            "Content-Disposition": f"attachment; filename=rustproof_scan_{scan_id[:8]}.json"
        }
    )

@api_router.post("/demo-scan")
async def create_demo_scan():
    """RustProof demo scan with comprehensive vulnerabilities"""
    demo_code = '''
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

#[program]
pub mod vulnerable_defi_vault {
    use super::*;
    
    // RP-001: Missing signer check - CRITICAL
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance -= amount; // Missing authority.is_signer check!
        Ok(())
    }
    
    // RP-002: Integer overflow - HIGH  
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance += amount; // Should use checked_add!
        Ok(())
    }
    
    // RP-004: PDA bump manipulation - CRITICAL
    pub fn create_vault(ctx: Context<CreateVault>, bump: u8) -> Result<()> {
        let seeds = &[b"vault", ctx.accounts.user.key().as_ref(), &[bump]];
        // Using user-provided bump instead of canonical!
        Ok(())
    }
    
    // RP-006: Slippage vulnerability - HIGH
    pub fn swap_tokens(ctx: Context<Swap>, amount_in: u64) -> Result<()> {
        let amount_out = amount_in * ctx.accounts.pool.exchange_rate;
        // No slippage protection!
        token::transfer(ctx.accounts.transfer_ctx(), amount_out)?;
        Ok(())
    }
    
    // RP-005: Oracle manipulation - CRITICAL
    pub fn liquidate(ctx: Context<Liquidate>) -> Result<()> {
        let price = ctx.accounts.price_feed.get_price();
        // No staleness or confidence checks!
        if ctx.accounts.position.collateral_value < price * LIQUIDATION_RATIO {
            // Execute liquidation
        }
        Ok(())
    }
    
    // RP-013: Clock manipulation - MEDIUM
    pub fn claim_rewards(ctx: Context<ClaimRewards>) -> Result<()> {
        let current_time = Clock::get()?.unix_timestamp;
        let rewards = (current_time - ctx.accounts.stake.last_claim) * REWARD_RATE;
        // No timestamp validation!
        Ok(())
    }
    
    // RP-007: Flash loan vulnerability - HIGH
    pub fn flash_borrow(ctx: Context<FlashBorrow>, amount: u64) -> Result<()> {
        // Borrow without atomic repayment validation
        ctx.accounts.vault.balance -= amount;
        // Missing: ensure repayment in same transaction
        Ok(())
    }
    
    // RP-010: CPI without validation - CRITICAL
    pub fn delegate_call(ctx: Context<DelegateCall>) -> Result<()> {
        let ix = create_instruction();
        invoke(&ix, &ctx.remaining_accounts)?; // No program validation!
        Ok(())
    }
}
'''
    
    # Generate session ID for demo
    session_id = str(uuid.uuid4())
    
    # Enhanced analysis
    vulnerabilities = await analyze_rust_code(demo_code, "vulnerable_defi_vault.rs")
    
    # Calculate enhanced metrics
    lines_analyzed = len(demo_code.split('\n'))
    metrics = SecurityMetrics(
        total_lines_analyzed=lines_analyzed,
        complexity_score=200,
        attack_surface_score=240,
        business_logic_score=150,
        defi_risk_score=300
    )
    
    scoring_result = calculate_enhanced_security_score(vulnerabilities, metrics)
    compliance_report = generate_compliance_report(vulnerabilities)
    remediation = calculate_remediation_metrics(vulnerabilities)
    
    # Count vulnerabilities by severity
    critical_count = sum(1 for v in vulnerabilities if v.severity == "Critical")
    high_count = sum(1 for v in vulnerabilities if v.severity == "High")
    medium_count = sum(1 for v in vulnerabilities if v.severity == "Medium")
    low_count = sum(1 for v in vulnerabilities if v.severity == "Low")
    
    demo_scan = ScanResult(
        status="completed",
        security_score=scoring_result["score"],
        file_count=1,
        vulnerabilities=vulnerabilities,
        total_vulnerabilities=len(vulnerabilities),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        security_metrics=metrics,
        compliance_report=compliance_report,
        risk_assessment=scoring_result["risk_level"],
        remediation_priority=remediation["priority_order"],
        session_id=session_id,
        file_name="vulnerable_defi_vault.rs"
    )
    
    await db.scans.insert_one(demo_scan.dict())
    return demo_scan

# WebSocket endpoint for real-time updates
@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await manager.connect(websocket)
    try:
        while True:
            # Send scan progress updates
            scan_data = await db.scans.find_one({"id": scan_id})
            if scan_data:
                await manager.send_message(json.dumps({
                    "type": "scan_update",
                    "data": scan_data
                }), websocket)
            
            await asyncio.sleep(1)  # Update every second
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
