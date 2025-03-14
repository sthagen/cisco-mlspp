#pragma once

#include <memory>

#include <bytes/bytes.h>
#include <namespace.h>

using namespace MLS_NAMESPACE::bytes_ns;

namespace MLS_NAMESPACE::hpke {

struct Digest
{
  enum struct ID
  {
    SHA256,
    SHA384,
    SHA512,
  };

  template<ID id>
  static const Digest& get();

  const ID id;

  bytes hash(const bytes& data) const;
  bytes hmac(const bytes& key, const bytes& data) const;

  const size_t hash_size;

private:
  explicit Digest(ID id);

  bytes hmac_for_hkdf_extract(const bytes& key, const bytes& data) const;
  friend struct HKDF;
};

} // namespace MLS_NAMESPACE::hpke
