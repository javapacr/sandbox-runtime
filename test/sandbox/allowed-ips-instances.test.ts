import { describe, it, expect, afterEach } from 'bun:test'
import {
  createSandboxManager,
  SandboxManager,
  type ISandboxManager,
} from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { isMacOS } from '../helpers/platform.js'

/**
 * Per-instance network.allowedIPs after the v0.0.72 closure port (#20):
 * getAllowedIPs() reads the instance's own closure config, so independent
 * createSandboxManager() instances carry isolated allowedIPs policy.
 * Profile-generation-level assertions only (no command execution) so the
 * test also runs in constrained environments.
 */
describe.if(isMacOS)(
  'macOS allowedIPs across independent manager instances',
  () => {
    const instances: ISandboxManager[] = []
    const make = (): ISandboxManager => {
      const m = createSandboxManager()
      instances.push(m)
      return m
    }
    afterEach(async () => {
      await Promise.allSettled(instances.splice(0).map(m => m.reset()))
      await SandboxManager.reset()
    })

    const configWith = (
      allowedIPs?: string[],
      allowedDomains: string[] = [],
    ): SandboxRuntimeConfig => ({
      network: {
        allowedDomains,
        deniedDomains: [],
        ...(allowedIPs !== undefined ? { allowedIPs } : {}),
      },
      filesystem: {
        denyRead: ['~/.ssh'],
        allowWrite: ['.', '/tmp'],
        denyWrite: ['.env'],
      },
    })

    it('honors per-instance allowedIPs without cross-instance bleed', async () => {
      const parent = make()
      const child = make()
      await Promise.all([
        parent.initialize(configWith(['10.0.0.0/23:9093'], ['example.com'])),
        child.initialize(configWith(undefined, ['example.com'])),
      ])

      const parentWrapped = await parent.wrapWithSandbox('echo hi')
      const childWrapped = await child.wrapWithSandbox('echo hi')

      // Parent carries the port-scoped rule; the instance without
      // allowedIPs must not inherit it.
      expect(parentWrapped).not.toBe('echo hi')
      expect(childWrapped).not.toBe('echo hi')
      expect(parentWrapped).toContain(
        '(allow network-outbound (remote ip "*:9093"))',
      )
      expect(childWrapped).not.toContain(
        '(allow network-outbound (remote ip "*:',
      )
      expect(parentWrapped).not.toContain('(allow network*)')
      expect(childWrapped).not.toContain('(allow network*)')

      // Interface getter reflects per-instance closure config.
      expect(parent.getAllowedIPs()).toEqual(['10.0.0.0/23:9093'])
      expect(child.getAllowedIPs()).toBeUndefined()
    })

    it('different instances may carry different allowedIPs sets', async () => {
      const a = make()
      const b = make()
      await Promise.all([
        a.initialize(configWith(['10.0.0.0/23:9093'], ['example.com'])),
        b.initialize(configWith(['10.1.2.3:8080'], ['example.com'])),
      ])

      const wrappedA = await a.wrapWithSandbox('echo hi')
      const wrappedB = await b.wrapWithSandbox('echo hi')

      expect(wrappedA).toContain(
        '(allow network-outbound (remote ip "*:9093"))',
      )
      expect(wrappedA).not.toContain(
        '(allow network-outbound (remote ip "*:8080"))',
      )
      expect(wrappedB).toContain(
        '(allow network-outbound (remote ip "*:8080"))',
      )
      expect(wrappedB).not.toContain(
        '(allow network-outbound (remote ip "*:9093"))',
      )
    })
  },
)
