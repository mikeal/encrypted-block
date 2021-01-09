/* globals describe, it */
import { encode, decode, crypto, name, code } from '../index.js'
import { sha256 as hasher } from 'multiformats/hashes/sha2'
import raw from 'multiformats/codecs/raw'
import { codec } from 'multiformats/codecs/codec'
import { randomBytes } from 'crypto'
import * as Block from 'multiformats/block'
import { deepStrictEqual as same } from 'assert'

const eb = codec({ encode, decode, name, code })

describe('encrypted-block', () => {
  it('encrypt/decrypt raw block', async () => {
    const { encrypt, decrypt } = crypto(randomBytes(32))
    const value = Buffer.allocUnsafe(128).fill('x')
    const block = await Block.encode({ value, hasher, codec: raw })
    const { value: encrypted } = await encrypt(block)
    const eBlock = await Block.encode({ value: encrypted, codec: eb, hasher })
    same(Buffer.compare(Buffer.from(value), Buffer.from(eBlock.bytes)) !== 0, true)

    const { value: val } = await Block.decode({ ...eBlock, codec: eb, hasher })
    const { cid, bytes } = await decrypt({ value: val })
    const dBlock = await Block.decode({ cid, bytes, codec: raw, hasher })
    same([...dBlock.value], [...value])
  })
})
