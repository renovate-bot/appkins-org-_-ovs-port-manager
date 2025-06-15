package manager

import (
	"context"
	"fmt"
	slices "slices"

	"github.com/appkins-org/ovs-port-manager/internal/models"
	"github.com/go-logr/logr"
	"github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/libovsdb/ovsdb"
)

// ovsService handles OVSDB interactions.
type ovsService struct {
	ovs    client.Client
	logger logr.Logger
}

// newOVSService creates a new ovsService.
func newOVSService(ovs client.Client, logger logr.Logger) *ovsService {
	return &ovsService{
		ovs:    ovs,
		logger: logger.WithName("ovsService"),
	}
}

// getRootUUID retrieves the root UUID from the Open_vSwitch table.
func (s *ovsService) getRootUUID(ctx context.Context) (string, error) {
	var rootUUID string
	// Iterate over the cache. Since we monitor Open_vSwitch, it should be cached.
	cache := s.ovs.Cache().Table("Open_vSwitch")
	if cache == nil {
		// This case should ideally not happen if monitoring is set up correctly.
		// Fallback to a direct list if cache is not populated for Open_vSwitch.
		s.logger.V(1).Info("Open_vSwitch table not found in cache, attempting direct list.")
		var ovsList []models.OpenvSwitch
		if err := s.ovs.List(ctx, &ovsList); err != nil {
			return "", fmt.Errorf("failed to list Open_vSwitch table: %w", err)
		}
		if len(ovsList) == 0 {
			return "", fmt.Errorf("no Open_vSwitch records found via direct list")
		}
		rootUUID = ovsList[0].UUID
	} else {
		for uuid := range cache.Rows() {
			rootUUID = uuid
			break // Take the first (and typically only) UUID
		}
	}

	if rootUUID == "" {
		return "", fmt.Errorf("no Open_vSwitch root UUID found")
	}
	s.logger.V(3).Info("Retrieved root UUID", "uuid", rootUUID)
	return rootUUID, nil
}

// ensureBridge creates an OVS bridge if it doesn't exist.
func (s *ovsService) ensureBridge(ctx context.Context, bridgeName, namedUUID string) error {
	var bridges []models.Bridge
	err := s.ovs.WhereCache(func(b *models.Bridge) bool {
		return b.Name == bridgeName
	}).List(ctx, &bridges)
	if err != nil {
		return fmt.Errorf("failed to list bridges from cache: %w", err)
	}

	if len(bridges) > 0 {
		s.logger.V(1).Info("Bridge already exists", "bridge", bridgeName)
		return nil
	}

	s.logger.V(1).Info("Creating bridge", "bridge", bridgeName)

	rootUUID, err := s.getRootUUID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get root UUID for bridge creation: %w", err)
	}

	bridge := models.Bridge{
		UUID:        namedUUID, // Named UUID for transaction
		Name:        bridgeName,
		Ports:       []string{},
		ExternalIDs: map[string]string{},
		OtherConfig: map[string]string{},
	}

	insertOp, err := s.ovs.Create(&bridge)
	if err != nil {
		return fmt.Errorf("failed to create bridge insert operation: %w", err)
	}

	ovsRow := models.OpenvSwitch{UUID: rootUUID}
	mutateOps, err := s.ovs.Where(&ovsRow).Mutate(&ovsRow, model.Mutation{
		Field:   &ovsRow.Bridges,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{bridge.UUID},
	})
	if err != nil {
		return fmt.Errorf("failed to create bridge mutation operation: %w", err)
	}

	operations := append(insertOp, mutateOps...)
	reply, err := s.ovs.Transact(ctx, operations...)
	if err != nil {
		return fmt.Errorf("failed to transact bridge creation for %s: %w", bridgeName, err)
	}

	if _, err := ovsdb.CheckOperationResults(reply, operations); err != nil {
		return fmt.Errorf("bridge creation transaction failed for %s: %w", bridgeName, err)
	}

	s.logger.V(1).
		Info("Bridge creation successful", "bridge", bridgeName, "uuid", reply[0].UUID.GoUUID)
	return nil
}

// removePortFromBridge removes a port from an OVS bridge.
func (s *ovsService) removePortFromBridge(ctx context.Context, portName string) error {
	s.logger.V(2).Info("Removing port from OVS bridge", "port", portName)

	var ports []models.Port
	err := s.ovs.WhereCache(func(p *models.Port) bool {
		return p.Name == portName
	}).List(ctx, &ports)
	if err != nil {
		return fmt.Errorf("failed to find port %s in cache: %w", portName, err)
	}

	if len(ports) == 0 {
		s.logger.V(1).Info("Port does not exist, nothing to remove", "port", portName)
		return nil
	}
	port := &ports[0]

	var bridges []models.Bridge
	err = s.ovs.WhereCache(func(b *models.Bridge) bool {
		return slices.Contains(b.Ports, port.UUID)
	}).List(ctx, &bridges)
	if err != nil {
		return fmt.Errorf("failed to find bridge containing port %s from cache: %w", portName, err)
	}

	operations := []ovsdb.Operation{}
	if len(bridges) > 0 {
		bridge := &bridges[0]
		mutateOp := ovsdb.Operation{
			Op:    ovsdb.OperationMutate,
			Table: models.BridgeTable,
			Where: []ovsdb.Condition{
				{
					Column:   "_uuid",
					Function: ovsdb.ConditionEqual,
					Value:    ovsdb.UUID{GoUUID: bridge.UUID},
				},
			},
			Mutations: []ovsdb.Mutation{{
				Column:  "ports",
				Mutator: ovsdb.MutateOperationDelete,
				Value:   ovsdb.OvsSet{GoSet: []any{ovsdb.UUID{GoUUID: port.UUID}}},
			}},
		}
		operations = append(operations, mutateOp)
	}

	deleteOps, err := s.ovs.Where(port).Delete()
	if err != nil {
		return fmt.Errorf("failed to create port delete operation for %s: %w", portName, err)
	}
	operations = append(operations, deleteOps...)

	results, err := s.ovs.Transact(ctx, operations...)
	if err != nil {
		return fmt.Errorf("failed to transact port removal for %s: %w", portName, err)
	}

	if len(results) > 0 && results[0].Error != "" {
		s.logger.Error(
			fmt.Errorf("%s", results[0].Error),
			"OVSDB operation error during port removal",
			"details",
			results[0].Details,
		)
	}

	s.logger.V(2).
		Info("Successfully removed port from OVS bridge", "port", portName, "transactionResults", len(results))
	return nil
}

// findPortsForContainer finds all OVS ports associated with a container.
func (s *ovsService) findPortsForContainer(
	ctx context.Context,
	containerID string,
) ([]string, error) {
	var interfaces []models.Interface
	err := s.ovs.WhereCache(func(i *models.Interface) bool {
		containerIDValue, exists := i.ExternalIDs["container_id"]
		return exists && containerIDValue == containerID
	}).List(ctx, &interfaces)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to find interfaces for container %s from cache: %w",
			containerID,
			err,
		)
	}

	var portNames []string
	for _, iface := range interfaces {
		portNames = append(portNames, iface.Name)
	}

	s.logger.V(3).
		Info("Found ports for container", "container_id", containerID[:12], "port_count", len(portNames), "ports", portNames)
	return portNames, nil
}

// getPortForContainerInterface finds a port for a container interface.
func (s *ovsService) getPortForContainerInterface(
	ctx context.Context,
	containerID, interfaceName string,
) (string, error) {
	var interfaces []models.Interface
	err := s.ovs.WhereCache(func(i *models.Interface) bool {
		containerIDMatch := i.ExternalIDs["container_id"] == containerID
		interfaceMatch := i.ExternalIDs["container_iface"] == interfaceName
		return containerIDMatch && interfaceMatch
	}).List(ctx, &interfaces)
	if err != nil {
		return "", fmt.Errorf(
			"failed to search for interfaces for %s/%s from cache: %w",
			containerID,
			interfaceName,
			err,
		)
	}

	if len(interfaces) == 0 {
		return "", nil
	}
	return interfaces[0].Name, nil
}

// getOvsPortByName retrieves an OVS port by its name.
// Returns (nil, nil) if not found, (*models.Port, nil) if found, or (nil, error) on error.
func (s *ovsService) getOvsPortByName(ctx context.Context, portName string) (*models.Port, error) {
	var ports []models.Port
	err := s.ovs.WhereCache(func(p *models.Port) bool {
		return p.Name == portName
	}).List(ctx, &ports)
	if err != nil {
		return nil, fmt.Errorf("failed to find port %s in cache: %w", portName, err)
	}
	if len(ports) == 0 {
		return nil, nil // Not found
	}
	return &ports[0], nil
}

// addPortToBridge adds a port to an OVS bridge with external IDs.
func (s *ovsService) addPortToBridge(
	ctx context.Context,
	bridgeName, portName string,
	externalIDs ...map[string]string,
) error {
	s.logger.V(2).Info("Adding port to OVS bridge", "bridge", bridgeName, "port", portName)

	var existingPortsOnBridge []models.Port
	err := s.ovs.WhereCache(func(p *models.Port) bool {
		return p.Name == portName
	}).List(ctx, &existingPortsOnBridge)
	if err != nil {
		return fmt.Errorf("failed to check existing ports for %s from cache: %w", portName, err)
	}

	if len(existingPortsOnBridge) > 0 {
		// Further check if this port is already on the *target* bridge.
		// This requires finding the bridge and checking its Ports list.
		var bridges []models.Bridge
		err = s.ovs.WhereCache(func(b *models.Bridge) bool {
			return b.Name == bridgeName
		}).List(ctx, &bridges)
		if err != nil {
			return fmt.Errorf(
				"failed to find bridge %s to check existing port: %w",
				bridgeName,
				err,
			)
		}
		if len(bridges) > 0 {
			bridge := &bridges[0]
			for _, portUUID := range bridge.Ports {
				if portUUID == existingPortsOnBridge[0].UUID {
					s.logger.V(1).
						Info("Port already exists on the target bridge", "bridge", bridgeName, "port", portName)
					// Potentially update external IDs if they differ
					return s.updateInterfaceExternalIDs(ctx, portName, externalIDs...)
				}
			}
		}
		s.logger.V(1).
			Info("Port exists but not on the target bridge or bridge not found, proceeding to add/update", "bridge", bridgeName, "port", portName)
	}

	var bridges []models.Bridge
	err = s.ovs.WhereCache(func(b *models.Bridge) bool {
		return b.Name == bridgeName
	}).List(ctx, &bridges)
	if err != nil {
		return fmt.Errorf("failed to find bridge %s from cache: %w", bridgeName, err)
	}
	if len(bridges) == 0 {
		return fmt.Errorf("bridge %s not found", bridgeName)
	}
	bridge := &bridges[0]

	interfaceExternalIDs := make(map[string]string)
	if len(externalIDs) > 0 {
		interfaceExternalIDs = externalIDs[0]
	}

	operations := []ovsdb.Operation{}
	var interfaceUUID string
	var existingInterfaces []models.Interface
	err = s.ovs.WhereCache(func(i *models.Interface) bool {
		return i.Name == portName
	}).List(ctx, &existingInterfaces)
	if err != nil {
		return fmt.Errorf(
			"failed to check existing interfaces for %s from cache: %w",
			portName,
			err,
		)
	}

	interfaceExists := len(existingInterfaces) > 0
	if interfaceExists {
		existingInterface := &existingInterfaces[0]
		interfaceUUID = existingInterface.UUID
		if len(interfaceExternalIDs) > 0 {
			needsUpdate := false
			updatedExternalIDs := make(map[string]string)
			for k, v := range existingInterface.ExternalIDs {
				updatedExternalIDs[k] = v
			}
			for k, v := range interfaceExternalIDs {
				if existingInterface.ExternalIDs[k] != v {
					needsUpdate = true
				}
				updatedExternalIDs[k] = v
			}
			if needsUpdate {
				existingInterface.ExternalIDs = updatedExternalIDs
				if ops, err := s.ovs.Where(existingInterface).Update(existingInterface, &existingInterface.ExternalIDs); err != nil {
					return fmt.Errorf(
						"failed to update interface external IDs for %s: %w",
						portName,
						err,
					)
				} else {
					operations = append(operations, ops...)
				}
			}
		}
		s.logger.V(2).Info("Using existing interface", "interface", portName, "uuid", interfaceUUID)
	} else {
		interfaceUUID = "iface-" + portName // More descriptive named UUID
		iface := &models.Interface{
			UUID:        interfaceUUID,
			Name:        portName,
			Type:        "", // OVS typically sets this, can be empty
			ExternalIDs: interfaceExternalIDs,
		}
		if ops, err := s.ovs.Create(iface); err != nil {
			return fmt.Errorf("failed to create interface operation for %s: %w", portName, err)
		} else {
			operations = append(operations, ops...)
		}
		s.logger.V(2).Info("Creating new interface", "interface", portName, "namedUUID", interfaceUUID)
	}

	var portUUID string
	var existingNamedPorts []models.Port // Changed from existingPorts to avoid conflict
	err = s.ovs.WhereCache(func(p *models.Port) bool {
		return p.Name == portName
	}).List(ctx, &existingNamedPorts)
	if err != nil {
		return fmt.Errorf(
			"failed to check existing ports with name %s from cache: %w",
			portName,
			err,
		)
	}

	portExists := len(existingNamedPorts) > 0
	if portExists {
		existingPort := &existingNamedPorts[0]
		portUUID = existingPort.UUID
		// Ensure port references the correct interface (newly created or existing)
		currentInterfaceCorrect := false
		for _, ref := range existingPort.Interfaces {
			if ref == interfaceUUID {
				currentInterfaceCorrect = true
				break
			}
		}
		if !currentInterfaceCorrect {
			existingPort.Interfaces = []string{interfaceUUID}
			if ops, err := s.ovs.Where(existingPort).Update(existingPort, &existingPort.Interfaces); err != nil {
				return fmt.Errorf("failed to update port interfaces for %s: %w", portName, err)
			} else {
				operations = append(operations, ops...)
			}
		}
		s.logger.V(2).Info("Using existing port", "port", portName, "uuid", portUUID)
	} else {
		portUUID = "ovsport-" + portName // More descriptive named UUID
		port := &models.Port{
			UUID:        portUUID,
			Name:        portName,
			Interfaces:  []string{interfaceUUID},
			ExternalIDs: map[string]string{},
		}
		if ops, err := s.ovs.Create(port); err != nil {
			return fmt.Errorf("failed to create port operation for %s: %w", portName, err)
		} else {
			operations = append(operations, ops...)
		}
		s.logger.V(2).Info("Creating new port", "port", portName, "namedUUID", portUUID)
	}

	portAlreadyInBridge := false
	for _, existingPortRef := range bridge.Ports {
		if existingPortRef == portUUID {
			portAlreadyInBridge = true
			break
		}
	}

	if !portAlreadyInBridge {
		if ops, err := s.ovs.Where(bridge).Mutate(bridge, model.Mutation{
			Field:   &bridge.Ports,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   []string{portUUID},
		}); err == nil {
			operations = append(operations, ops...)
		} else {
			return fmt.Errorf("failed to create bridge mutation for port %s: %w", portName, err)
		}
	}

	if len(operations) == 0 {
		s.logger.V(2).
			Info("No OVSDB operations needed for port, already configured", "bridge", bridgeName, "port", portName)
		return nil
	}

	s.logger.V(2).
		Info("Executing OVSDB transaction", "bridge", bridgeName, "port", portName, "operationCount", len(operations))
	results, err := s.ovs.Transact(ctx, operations...)
	if err != nil {
		s.logger.Error(
			err,
			"OVS port update transaction failed",
			"bridge",
			bridgeName,
			"port",
			portName,
		)
		return fmt.Errorf("OVS transaction failed for port %s: %w", portName, err)
	}
	if _, err := ovsdb.CheckOperationResults(results, operations); err != nil {
		s.logger.Error(
			err,
			"OVS transaction failed - detailed operation results",
			"bridge",
			bridgeName,
			"port",
			portName,
		)
		for i, result := range results {
			if result.Error != "" {
				s.logger.Error(
					nil,
					"OVSDB operation failed",
					"operationIndex",
					i,
					"error",
					result.Error,
					"details",
					result.Details,
				)
			}
		}
		return fmt.Errorf("OVS transaction check failed for port %s: %w", portName, err)
	}

	s.logger.V(2).
		Info("Successfully added/updated port in OVS bridge", "bridge", bridgeName, "port", portName, "transactionResults", len(results))
	return nil
}

// updateInterfaceExternalIDs updates the external IDs of an existing interface if necessary.
func (s *ovsService) updateInterfaceExternalIDs(
	ctx context.Context,
	portName string,
	externalIDs ...map[string]string,
) error {
	if len(externalIDs) == 0 || len(externalIDs[0]) == 0 {
		return nil // No external IDs to update
	}
	targetExternalIDs := externalIDs[0]

	var existingInterfaces []models.Interface
	err := s.ovs.WhereCache(func(i *models.Interface) bool {
		return i.Name == portName
	}).List(ctx, &existingInterfaces)
	if err != nil {
		return fmt.Errorf("failed to find interface %s to update external IDs: %w", portName, err)
	}
	if len(existingInterfaces) == 0 {
		s.logger.V(1).Info("Interface not found, cannot update external IDs", "interface", portName)
		return nil // Or an error, depending on desired strictness
	}

	existingInterface := &existingInterfaces[0]
	needsUpdate := false
	newExternalIDs := make(map[string]string)
	// Copy existing IDs first
	for k, v := range existingInterface.ExternalIDs {
		newExternalIDs[k] = v
	}
	// Check and update with target IDs
	for k, v := range targetExternalIDs {
		if existingInterface.ExternalIDs[k] != v {
			needsUpdate = true
		}
		newExternalIDs[k] = v
	}

	if needsUpdate {
		s.logger.V(2).
			Info("Updating external IDs for interface", "interface", portName, "newIDs", newExternalIDs)
		existingInterface.ExternalIDs = newExternalIDs
		ops, err := s.ovs.Where(existingInterface).
			Update(existingInterface, &existingInterface.ExternalIDs)
		if err != nil {
			return fmt.Errorf(
				"failed to create update operation for interface %s external IDs: %w",
				portName,
				err,
			)
		}
		results, err := s.ovs.Transact(ctx, ops...)
		if err != nil {
			return fmt.Errorf(
				"failed to transact update for interface %s external IDs: %w",
				portName,
				err,
			)
		}
		if _, err := ovsdb.CheckOperationResults(results, ops); err != nil {
			return fmt.Errorf(
				"update transaction for interface %s external IDs failed: %w",
				portName,
				err,
			)
		}
		s.logger.V(2).Info("Successfully updated external IDs for interface", "interface", portName)
	}
	return nil
}

// setVLAN sets the VLAN tag for a port.
func (s *ovsService) setVLAN(ctx context.Context, portName string, vlanTag int) error {
	var ports []models.Port
	err := s.ovs.WhereCache(func(p *models.Port) bool {
		return p.Name == portName
	}).List(ctx, &ports)
	if err != nil {
		return fmt.Errorf("failed to find OVS port %s for VLAN tagging: %w", portName, err)
	}
	if len(ports) == 0 {
		return fmt.Errorf("OVS port %s not found for VLAN tagging", portName)
	}

	portRow := &ports[0]
	// Ensure Tag is a pointer to an int, as per libovsdb model for optional integers.
	if portRow.Tag != nil && *portRow.Tag == vlanTag {
		s.logger.V(2).Info("VLAN tag already set correctly", "port", portName, "vlan", vlanTag)
		return nil
	}

	newVlanTag := vlanTag // Ensure it's a new variable for the pointer
	portRow.Tag = &newVlanTag

	ops, err := s.ovs.Where(portRow).Update(portRow, &portRow.Tag)
	if err != nil {
		return fmt.Errorf("failed to create VLAN update operation for port %s: %w", portName, err)
	}

	results, err := s.ovs.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("failed to transact VLAN update for port %s: %w", portName, err)
	}
	if _, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		// If it failed because the tag was already set (e.g. by another process),
		// and the current tag matches, consider it a success.
		var updatedPorts []models.Port
		if listErr := s.ovs.WhereCache(func(p *models.Port) bool { return p.Name == portName }).List(ctx, &updatedPorts); listErr == nil &&
			len(updatedPorts) > 0 {
			if updatedPorts[0].Tag != nil && *updatedPorts[0].Tag == vlanTag {
				s.logger.V(1).
					Info("VLAN tag was already set to the target value, considering successful despite transaction error", "port", portName, "vlan", vlanTag, "original_error", err)
				return nil
			}
		}
		return fmt.Errorf("VLAN update transaction check failed for port %s: %w", portName, err)
	}

	s.logger.Info("Successfully set VLAN", "port", portName, "vlan", vlanTag)
	return nil
}
