defmodule Ctrld.Repo.Migrations.CreateCertificateAuthorities do
  use Ecto.Migration

  def change do
    create table(:certificate_authorities) do
      add :name, :string, null: false
      # The algorithm is a column and not an assumption: moving the fleet to
      # another signature algorithm is then a re-issuance against rows that
      # already say what they are, rather than a schema change.
      add :key_algorithm, :string, null: false
      add :signature_algorithm, :string, null: false
      add :certificate_der, :binary, null: false
      add :serial, :string, null: false
      add :subject_common_name, :string, null: false
      add :spki_fingerprint, :string, null: false
      add :not_before, :utc_datetime, null: false
      add :not_after, :utc_datetime, null: false
      # The private key sealed by Ctrld.Vault: never the key itself, and the
      # three fields the cipher needs kept together so a row is self-contained.
      add :sealed_key, :binary, null: false
      add :sealed_key_iv, :binary, null: false
      add :sealed_key_tag, :binary, null: false
      add :retired_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:certificate_authorities, [:spki_fingerprint])

    # At most one authority is signing at any moment. Retiring one is what
    # makes room for the next, so the constraint is over the live rows alone.
    # Not an index on `retired_at` itself: two NULLs are distinct to a unique
    # index, so that would constrain nothing. Indexing the predicate instead —
    # which is true for every row the partial index covers — is what makes "at
    # most one live authority" a rule the database keeps.
    create unique_index(:certificate_authorities, ["((retired_at IS NULL))"],
             where: "retired_at IS NULL",
             name: :certificate_authorities_one_active_index
           )

    create table(:endpoint_certificates) do
      add :certificate_authority_id,
          references(:certificate_authorities, on_delete: :restrict),
          null: false

      add :endpoint, :string, null: false
      add :key_algorithm, :string, null: false
      add :signature_algorithm, :string, null: false
      add :certificate_der, :binary, null: false
      add :serial, :string, null: false
      add :spki_fingerprint, :string, null: false
      add :not_before, :utc_datetime, null: false
      add :not_after, :utc_datetime, null: false
      add :sealed_key, :binary, null: false
      add :sealed_key_iv, :binary, null: false
      add :sealed_key_tag, :binary, null: false
      add :retired_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create index(:endpoint_certificates, [:certificate_authority_id])

    create unique_index(:endpoint_certificates, ["((retired_at IS NULL))"],
             where: "retired_at IS NULL",
             name: :endpoint_certificates_one_active_index
           )
  end
end
