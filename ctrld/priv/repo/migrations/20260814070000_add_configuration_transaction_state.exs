defmodule Ctrld.Repo.Migrations.AddConfigurationTransactionState do
  use Ecto.Migration

  # The four instants a configuration change passes through on its way to an
  # appliance, and this server had none of them until it could drive one.
  #
  # Each column is a thing that HAPPENED and not a state somebody decided: two
  # record what this server sent down the channel, and two record what the
  # appliance said back. The lifecycle is derived from them by
  # `Ctrld.Appliances.ConfigurationVersion.state/1`, on the same reasoning the
  # inventory derives an appliance's status — a stored state is a value that can
  # disagree with the facts under it, and a version's history is exactly the sort
  # of thing an operator has to be able to believe.
  #
  # `staged_at` and `committed_at` are this server's sends. `validated_at` and
  # `validation_result` are the appliance's one answer: the result line its
  # validating domain composed, kept verbatim because it names the rule that
  # refused a document and the offset that places it, and this server has no
  # business paraphrasing a verdict it did not reach.
  #
  # `confirmed_at` is the send that makes a provisional commit permanent, and it
  # necessarily belongs to a LATER connection than `committed_at`: the appliance
  # ends the session on a commit, so a confirmation can only arrive over a fresh
  # one. That is the protocol's rule rather than this schema's, and the two
  # columns are what let an operator see the pair.
  #
  # There is deliberately no column for a rollback. An unconfirmed commit is
  # undone by the appliance's own deadline, over no frame this server sends and
  # with no frame coming back, so a rollback is not a fact this server holds —
  # and a column nothing ever writes reads as a fact nobody has.
  def change do
    alter table(:configuration_versions) do
      add(:staged_at, :utc_datetime)
      add(:validated_at, :utc_datetime)
      # Text rather than a bounded string, and the reason is the adversary: the
      # line arrives from a semi-trusted appliance, and the only bound the wire
      # imposes on it is the frame's payload bound. A narrower column would turn
      # a peer's long line into a database error on a path a peer paces, where
      # text makes every line the codec accepted a line this server can store.
      add(:validation_result, :text)
      add(:committed_at, :utc_datetime)
      add(:confirmed_at, :utc_datetime)
    end
  end
end
