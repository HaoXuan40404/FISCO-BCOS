/**
 *  Copyright (C) 2024 FISCO BCOS.
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
 * @brief implementation for range-proof
 * @file RangeProof.h
 * @date 2025.02.07
 * @author asherli
 */

#pragma once
#include <bcos-utilities/Common.h>
#include <wedpr-crypto/WedprRangeProof.h>
#include <memory>

namespace bcos::crypto {
class RangeProofZkp
{
public:
    using Ptr = std::shared_ptr<RangeProofZkp>;
    RangeProofZkp(size_t _pointLen) : m_pointLen(_pointLen) {}
    RangeProofZkp() = default;
    virtual ~RangeProofZkp() {}

    // Copy constructor
    RangeProofZkp(const RangeProofZkp& other) = default;

    // Copy assignment operator
    RangeProofZkp& operator=(const RangeProofZkp& other)
    {
        if (this != &other)
        {
            m_pointLen = other.m_pointLen;
        }
        return *this;
    }

    // Move constructor
    RangeProofZkp(RangeProofZkp&& other) noexcept : m_pointLen(other.m_pointLen)
    {
        other.m_pointLen = 0;
    }

    // Move assignment operator
    RangeProofZkp& operator=(RangeProofZkp&& other) noexcept
    {
        if (this != &other)
        {
            m_pointLen = other.m_pointLen;
            other.m_pointLen = 0;
        }
        return *this;
    }

    // wedpr_verify_range_proof
    bool verifyRangeProof(bytes const& cPointData,
        bytes const& rangeProof, bytes const& blindingBasePointData);
    
        // wedpr_verify_range_proof_without_basepoint
    bool verifyRangeProofWithoutBasePoint(bytes const& cPointData,
        bytes const& rangeProof);

private:
    size_t m_pointLen = 32;
};
}  // namespace bcos::crypto 
