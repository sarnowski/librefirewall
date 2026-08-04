defmodule Ctrld.Repo.Migrations.CreateAppliances do
  use Ecto.Migration

  def change do
    create table(:appliances) do
      # The device identifier the appliance minted and put in its request's
      # common name. It is the appliance's name in this system; the display
      # name below is the administrator's word for it and decides nothing.
      add :device_id, :string, null: false
      add :name, :string, null: false
      add :spki_fingerprint, :string, null: false
      add :csr_pem, :text, null: false
      add :csr_received_at, :utc_datetime, null: false

      add :certificate_authority_id,
          references(:certificate_authorities, on_delete: :restrict),
          null: false

      add :certificate_der, :binary, null: false
      add :certificate_serial, :string, null: false
      add :certificate_issued_at, :utc_datetime, null: false
      add :certificate_not_after, :utc_datetime, null: false
      # The endpoint this appliance was told to dial, recorded as issued: it
      # can never be changed over the channel, so what the package said is
      # what the appliance will believe for the rest of its life.
      add :endpoint, :string, null: false
      add :onboarded_by_id, references(:users, on_delete: :nilify_all)

      timestamps(type: :utc_datetime)
    end

    create unique_index(:appliances, [:device_id])
    create unique_index(:appliances, [:spki_fingerprint])
    create index(:appliances, [:certificate_authority_id])

    create table(:configuration_versions) do
      add :appliance_id, references(:appliances, on_delete: :delete_all), null: false
      add :generation, :integer, null: false
      add :document, :text, null: false
      add :document_sha256, :string, null: false
      add :author_id, references(:users, on_delete: :nilify_all)

      timestamps(type: :utc_datetime)
    end

    create unique_index(:configuration_versions, [:appliance_id, :generation])
  end
end
