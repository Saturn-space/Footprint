import dns from 'dns';
import { ScopeValidationResult, Investigation } from '../../types/models';
import { serverRepos } from '../db/repositories';

// IPv4 Regex
const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;
// IPv6 Regex
const IPV6_REGEX = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
// Domain RFC 1035 regex
const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
// CIDR Regex
const CIDR_REGEX = /^(\d{1,3}\.){3}\d{1,3}\/(\d{1,2})$/;

export function isValidIPv4(ip: string): boolean {
  if (!IPV4_REGEX.test(ip)) return false;
  const parts = ip.split('.').map(Number);
  return parts.every(p => p >= 0 && p <= 255);
}

export function isValidIPv6(ip: string): boolean {
  return IPV6_REGEX.test(ip);
}

export function isValidDomain(domain: string): boolean {
  const normalized = domain.trim().toLowerCase().replace(/\.$/, '');
  if (normalized.length > 253) return false;
  return DOMAIN_REGEX.test(normalized);
}

export function isValidCIDR(cidr: string): boolean {
  const match = cidr.match(CIDR_REGEX);
  if (!match) return false;
  const ip = cidr.split('/')[0];
  const prefix = parseInt(match[2], 10);
  return isValidIPv4(ip) && prefix >= 0 && prefix <= 32;
}

export function ipToLong(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

export function isIpInCidr(ip: string, cidr: string): boolean {
  if (!isValidIPv4(ip) || !isValidCIDR(cidr)) return false;
  const [rangeIp, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  const ipNum = ipToLong(ip);
  const rangeNum = ipToLong(rangeIp);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipNum & mask) === (rangeNum & mask);
}

export class ScopeValidatorService {
  /**
   * Validate a target against an investigation scope
   */
  async validateTarget(
    investigation: Investigation,
    rawTarget: string,
    isTargetActiveCheck: boolean = false
  ): Promise<ScopeValidationResult> {
    const cleanTarget = rawTarget.trim().toLowerCase().replace(/\.$/, '');
    const now = new Date();
    const expiry = new Date(investigation.authorization.expiryDate);
    const isExpired = expiry.getTime() < now.getTime();

    let targetType: ScopeValidationResult['targetType'] = 'unknown';
    if (isValidIPv4(cleanTarget)) targetType = 'ipv4';
    else if (isValidIPv6(cleanTarget)) targetType = 'ipv6';
    else if (isValidCIDR(cleanTarget)) targetType = 'cidr';
    else if (isValidDomain(cleanTarget)) targetType = 'domain';

    let isAllowlistedForPassive = false;
    let isAllowlistedForActive = false;
    const scopeMatches: ScopeValidationResult['scopeMatches'] = {};

    // 1. Check Passive Allowlist
    for (const ownedDomain of investigation.scope.ownedDomains) {
      const normDomain = ownedDomain.trim().toLowerCase();
      if (cleanTarget === normDomain || cleanTarget.endsWith(`.${normDomain}`)) {
        isAllowlistedForPassive = true;
        scopeMatches.matchedDomain = normDomain;
        break;
      }
    }

    if (investigation.scope.passiveOnlyTargets.some(t => t.toLowerCase() === cleanTarget)) {
      isAllowlistedForPassive = true;
    }

    // 2. Check Active Allowlist
    if (investigation.authorization.activeScanningEnabled && !isExpired) {
      // Check explicit active target IPs
      if (investigation.scope.activeTargets.some(t => t.toLowerCase() === cleanTarget)) {
        isAllowlistedForActive = true;
        scopeMatches.matchedIP = cleanTarget;
      }

      // Check approved CIDRs
      if (targetType === 'ipv4') {
        for (const cidr of investigation.scope.approvedCIDRs) {
          if (isIpInCidr(cleanTarget, cidr)) {
            isAllowlistedForActive = true;
            scopeMatches.matchedCIDR = cidr;
            break;
          }
        }
      }
    }

    // 3. If target is a domain and active check is requested, re-resolve domain
    let resolvedIPs: string[] | undefined;
    let activeResolutionPassed = false;

    if (targetType === 'domain' && isTargetActiveCheck) {
      try {
        const resolved = await dns.promises.resolve4(cleanTarget);
        resolvedIPs = resolved;

        for (const ip of resolved) {
          if (investigation.scope.activeTargets.includes(ip)) {
            activeResolutionPassed = true;
            scopeMatches.matchedIP = ip;
            break;
          }
          for (const cidr of investigation.scope.approvedCIDRs) {
            if (isIpInCidr(ip, cidr)) {
              activeResolutionPassed = true;
              scopeMatches.matchedCIDR = cidr;
              break;
            }
          }
        }

        if (activeResolutionPassed) {
          isAllowlistedForActive = true;
        }
      } catch (dnsErr) {
        // Domain did not resolve
        resolvedIPs = [];
      }
    }

    // Check exclusions
    for (const excluded of investigation.scope.excludedTargets) {
      const normEx = excluded.toLowerCase();
      if (normEx.startsWith('*.')) {
        const suffix = normEx.slice(2);
        if (cleanTarget.endsWith(suffix)) {
          isAllowlistedForActive = false;
          isAllowlistedForPassive = false;
          break;
        }
      } else if (cleanTarget === normEx) {
        isAllowlistedForActive = false;
        isAllowlistedForPassive = false;
        break;
      }
    }

    let isValid = isTargetActiveCheck ? isAllowlistedForActive : (isAllowlistedForPassive || isAllowlistedForActive);
    let blockReason: string | undefined;

    if (isExpired) {
      isValid = false;
      blockReason = `Authorization expired on ${investigation.authorization.expiryDate}`;
    } else if (isTargetActiveCheck && !investigation.authorization.activeScanningEnabled) {
      isValid = false;
      blockReason = 'Active scanning is disabled by investigation authorization policy';
    } else if (isTargetActiveCheck && !isAllowlistedForActive) {
      isValid = false;
      blockReason = `Target "${cleanTarget}" is not in the active scanning allowlist (${investigation.scope.activeTargets.join(', ') || 'none'})`;
    } else if (!isAllowlistedForPassive && !isAllowlistedForActive) {
      isValid = false;
      blockReason = `Target "${cleanTarget}" does not match approved domains or IP scopes`;
    }

    return {
      isValid,
      target: rawTarget,
      normalizedTarget: cleanTarget,
      targetType,
      isAllowlistedForPassive,
      isAllowlistedForActive,
      resolvedIPs,
      authorizationExpired: isExpired,
      authorizationValidUntil: investigation.authorization.expiryDate,
      blockReason,
      scopeMatches
    };
  }

  /**
   * Enforces scope and logs denial to audit log if blocked
   */
  async enforceScope(
    investigation: Investigation,
    target: string,
    actionName: string,
    actor: string,
    isActiveOperation: boolean = false,
    requestId?: string
  ): Promise<ScopeValidationResult> {
    const result = await this.validateTarget(investigation, target, isActiveOperation);

    if (!result.isValid) {
      await serverRepos.audit.logEvent({
        investigationId: investigation.id,
        timestamp: new Date().toISOString(),
        actor,
        action: 'SCOPE_ENFORCEMENT_BLOCKED',
        category: 'authorization',
        targetResource: target,
        details: `BLOCKED operation "${actionName}": ${result.blockReason}. (Req: ${requestId || 'internal'})`,
        status: 'denied'
      });
    }

    return result;
  }
}

export const scopeValidator = new ScopeValidatorService();
