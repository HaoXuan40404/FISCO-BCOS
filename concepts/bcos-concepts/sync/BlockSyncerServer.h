#pragma once

#include "SyncBlockMessages.h"
#include <concepts>

namespace bcos::concepts::sync
{

template <class Impl>
class SyncBlockServerBase
{
public:
    auto getBlock(RequestBlock auto const& request) -> ResponseBlock auto
    {
        return impl().impl_getBlock(request);
    }

    auto getTransactionWithProof(bcos::concepts::ByteBuffer auto const& hash)
        -> bcos::concepts::transaction::Transaction auto
    {
        return impl().impl_getTransactionWithProof(hash);
    }

private:
    friend Impl;
    SyncBlockServerBase() = default;
    auto& impl() { return static_cast<Impl&>(*this); }
};

template <class Impl>
concept SyncBlockServer = std::derived_from<Impl, SyncBlockServerBase<Impl>>;

}  // namespace bcos::concepts::sync