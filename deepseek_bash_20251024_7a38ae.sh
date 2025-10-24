#!/bin/bash

echo "=== Safe OVS Setup ==="

# Интерфейсы и настройки (ЗАМЕНИТЕ НА СВОИ)
PHYSICAL_INTERFACES=("ens18" "ens19")
BRIDGE_IP="192.168.2.1/24"
CONTROLLER_IP="192.168.2.1:6633"

# 1. Останавливаем OVS
echo "Stopping OVS..."
systemctl stop openvswitch

# 2. Очищаем старые конфигурации
echo "Cleaning old configurations..."
ovs-vsctl del-br br0 2>/dev/null || true

# 3. Восстанавливаем физические интерфейсы
for iface in "${PHYSICAL_INTERFACES[@]}"; do
    echo "Restoring interface $iface..."
    ip link set $iface up
    ip addr flush dev $iface 2>/dev/null || true
done

# 4. Перезапускаем сеть
echo "Restarting network..."
systemctl restart network

# 5. Создаем bridge
echo "Creating OVS bridge..."
ovs-vsctl add-br br0

# 6. Добавляем физические порты в bridge
for iface in "${PHYSICAL_INTERFACES[@]}"; do
    echo "Adding port $iface to bridge..."
    ovs-vsctl add-port br0 $iface
done

# 7. Настраиваем bridge
echo "Configuring bridge..."
ip addr add $BRIDGE_IP dev br0
ip link set br0 up

# 8. Настраиваем контроллер (ОПЦИОНАЛЬНО - закомментируйте если не нужен)
echo "Setting controller..."
ovs-vsctl set-controller br0 tcp:$CONTROLLER_IP

# 9. Запускаем OVS
echo "Starting OVS..."
systemctl start openvswitch

# 10. Проверяем
echo "=== Verification ==="
ovs-vsctl show
echo "---"
ip addr show br0
echo "---"
ovs-ofctl show br0

echo "Setup complete!"