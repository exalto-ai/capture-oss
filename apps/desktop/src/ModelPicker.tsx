import { Menu } from '@mantine/core';
import { Check, ChevronDown } from 'lucide-react';
import type { ChatModel, Connection, ConnectionId } from './builtinBridge';
import { connectionNames } from './ProviderConnections';
import { SfSymbol } from './SfSymbol';

export type Catalog = { status: string; models: ChatModel[]; loading: boolean; error: string };
export type Choice = { connection: ConnectionId; model: string };

/** Locked and expired connections cannot list models until they are fixed in Connections. */
export const blockedAction: Record<string, string> = {
  locked: 'Unlock in Connections',
  reconnect: 'Reconnect in Connections',
};

const key = (choice: Choice) => `${choice.connection}:${choice.model}`;

function Marker({ status }: { status?: string }) {
  return <span className="chat-chip-mark" data-state={status} aria-hidden="true" />;
}

/**
 * One pop-up button for the model. Its menu lists each connection as a
 * section of models, so picking a model also picks the connection that
 * carries it.
 */
export function ModelPicker({
  connections,
  catalogs,
  choice,
  disabled,
  onChoose,
  onRetry,
  onManage,
}: {
  connections: Connection[];
  catalogs: Partial<Record<ConnectionId, Catalog>>;
  choice: Choice | null;
  disabled: boolean;
  onChoose: (choice: Choice) => void;
  onRetry: (connection: Connection) => void;
  onManage: () => void;
}) {
  const current = choice && catalogs[choice.connection]?.models.find((m) => m.id === choice.model);
  const loading = connections.some((c) => catalogs[c.id]?.loading);
  const label = current?.name ?? (loading ? 'Loading models…' : 'Choose a model');
  const status = connections.find((c) => c.id === choice?.connection)?.status;
  const options = new Map(
    connections.flatMap((connection) =>
      blockedAction[connection.status]
        ? []
        : (catalogs[connection.id]?.models ?? []).map((model) => {
            const option = { connection: connection.id, model: model.id };
            return [key(option), option] as const;
          }),
    ),
  );
  return (
    <Menu
      position="top-start"
      offset={6}
      withinPortal={false}
      disabled={disabled}
      checkIcon={<SfSymbol name="checkmark" fallback={Check} size={11} weight="semibold" />}
      classNames={{
        dropdown: 'chat-menu',
        item: 'chat-menu-item',
        itemIndicator: 'chat-menu-indicator',
        label: 'chat-menu-label',
        divider: 'chat-menu-divider',
      }}
    >
      <Menu.Target>
        <button
          type="button"
          className="chat-chip"
          aria-label={
            current && choice
              ? `Model: ${current.name}, ${connectionNames[choice.connection]}`
              : `Model: ${label}`
          }
          title={choice ? connectionNames[choice.connection] : undefined}
          disabled={disabled}
        >
          {current && <Marker status={status} />}
          <span className="chat-chip-label">{label}</span>
          {!disabled && (
            <SfSymbol name="chevron.down" fallback={ChevronDown} size={10} weight="semibold" />
          )}
        </button>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.RadioGroup
          value={choice ? key(choice) : null}
          onChange={(value) => {
            const picked = options.get(value);
            if (picked) onChoose(picked);
          }}
        >
          {connections.map((connection) => {
            const catalog = catalogs[connection.id];
            const name = connectionNames[connection.id];
            const blocked = blockedAction[connection.status];
            return (
              <div role="group" aria-label={name} key={connection.id}>
                <Menu.Label>
                  <Marker status={connection.status} />
                  {name}
                </Menu.Label>
                {blocked ? (
                  <Menu.Item className="is-inset" onClick={onManage}>
                    {blocked}
                  </Menu.Item>
                ) : catalog?.loading || !catalog ? (
                  <Menu.Item className="is-inset" disabled>
                    Loading models…
                  </Menu.Item>
                ) : catalog.error ? (
                  <>
                    <p className="chat-menu-note" role="alert">
                      {catalog.error}
                    </p>
                    <Menu.Item
                      className="is-inset"
                      closeMenuOnClick={false}
                      onClick={() => onRetry(connection)}
                    >
                      Retry models
                    </Menu.Item>
                  </>
                ) : (
                  catalog.models.map((model) => (
                    <Menu.RadioItem
                      key={model.id}
                      value={key({ connection: connection.id, model: model.id })}
                      closeMenuOnClick
                    >
                      {model.name}
                    </Menu.RadioItem>
                  ))
                )}
              </div>
            );
          })}
        </Menu.RadioGroup>
        <Menu.Divider />
        <Menu.Item onClick={onManage}>Manage connections…</Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}
