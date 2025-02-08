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

#include "RangeProofZkp.h"
#include "bcos-crypto/zkp/Common.h"

using namespace bcos::crypto;


// wedpr_verify_range_proof
bool RangeProofZkp::verifyRangeProof(
    bytes const& cPointData, bytes const& rangeProof, bytes const& blindingBasePointData)
{
    auto cPoint = bytesToInputBuffer(cPointData, m_pointLen);
    CInputBuffer proof{(const char*)rangeProof.data(), rangeProof.size()};
    auto blindingBasePoint = bytesToInputBuffer(blindingBasePointData, m_pointLen);
    auto ret = wedpr_verify_range_proof(&cPoint, &proof, &blindingBasePoint);
    return ret == WEDPR_SUCCESS;
}

// wedpr_verify_range_proof_without_basepoint
bool RangeProofZkp::verifyRangeProofWithoutBasePoint(
    bytes const& cPointData, bytes const& rangeProof)
{
    auto cPoint = bytesToInputBuffer(cPointData, m_pointLen);
    CInputBuffer proof{(const char*)rangeProof.data(), rangeProof.size()};
    auto ret = wedpr_verify_range_proof_without_basepoint(&cPoint, &proof);
    return ret == WEDPR_SUCCESS;
}