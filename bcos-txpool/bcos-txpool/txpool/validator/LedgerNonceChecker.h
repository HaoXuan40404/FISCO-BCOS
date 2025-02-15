/**
 *  Copyright (C) 2021 FISCO BCOS.
 *  SPDX-License-Identifier: Apache-2.0
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * @brief implementation for ledger nonce-checker
 * @file LedgerNonceChecker.h
 * @author: yujiechen
 * @date 2021-05-10
 */
#pragma once
#include "bcos-txpool/txpool/validator/TxPoolNonceChecker.h"
#include <bcos-framework/ledger/LedgerInterface.h>

namespace bcos::txpool
{
class LedgerNonceChecker : public TxPoolNonceChecker
{
public:
    LedgerNonceChecker(
        std::shared_ptr<std::map<int64_t, bcos::protocol::NonceListPtr> > _initialNonces,
        bcos::protocol::BlockNumber _blockNumber, int64_t _blockLimit, bool _checkBlockLimit)
      : TxPoolNonceChecker(),
        m_blockNumber(_blockNumber),
        m_blockLimit(_blockLimit),
        m_checkBlockLimit(_checkBlockLimit)
    {
        if (_initialNonces)
        {
            initNonceCache(std::move(_initialNonces));
        }
    }
    bcos::protocol::TransactionStatus checkNonce(const bcos::protocol::Transaction& _tx) override;

    void batchInsert(bcos::protocol::BlockNumber _batchId,
        bcos::protocol::NonceListPtr const& _nonceList) override;

protected:
    virtual bcos::protocol::TransactionStatus checkBlockLimit(
        const bcos::protocol::Transaction& _tx);
    void initNonceCache(
        std::shared_ptr<std::map<int64_t, bcos::protocol::NonceListPtr> > _initialNonces);

private:
    std::atomic<bcos::protocol::BlockNumber> m_blockNumber = {0};
    int64_t m_blockLimit;
    bool m_checkBlockLimit = true;

    /// cache the block nonce to in case of accessing the DB to get nonces of given block frequently
    /// key: block number
    /// value: all the nonces of a given block
    /// we cache at most m_blockLimit entries(occupy about 32KB)
    std::map<int64_t, bcos::protocol::NonceListPtr> m_blockNonceCache;
    mutable SharedMutex x_blockNonceCache;
};
}  // namespace bcos::txpool