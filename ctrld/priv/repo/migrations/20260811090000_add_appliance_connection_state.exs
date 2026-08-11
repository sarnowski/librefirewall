defmodule Ctrld.Repo.Migrations.AddApplianceConnectionState do
  use Ecto.Migration

  # The two facts a channel session establishes, and the inventory had neither
  # until there was a channel to establish them.
  #
  # `connected_since` is a live session and not a remembered one: it is set when
  # a session opens, cleared when it closes, and cleared for every row when the
  # listener starts, because a session cannot outlive the process that held it.
  # That is what keeps "online" from being a value that survives a restart and
  # reads as a fact.
  #
  # `last_seen_at` is the remembered half: the last instant a session was
  # observed, which is what tells an appliance that has been away from one that
  # has never dialled at all. Neither column carries a status — status stays
  # derived, so there is no stored value that can disagree with the two facts
  # under it.
  def change do
    alter table(:appliances) do
      add(:connected_since, :utc_datetime)
      add(:last_seen_at, :utc_datetime)
    end
  end
end
