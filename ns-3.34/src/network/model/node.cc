/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2006 Georgia Tech Research Corporation, INRIA
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: George F. Riley<riley@ece.gatech.edu>
 *          Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */

#include <iostream>

#include "node.h"
#include "node-list.h"
#include "net-device.h"
#include "application.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/object-vector.h"
#include "ns3/uinteger.h"
#include "ns3/log.h"
#include "ns3/assert.h"
#include "ns3/global-value.h"
#include "ns3/boolean.h"
#include "ns3/vector.h"


namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("Node");

NS_OBJECT_ENSURE_REGISTERED (Node);

/**
 * \relates Node
 * \anchor GlobalValueChecksumEnabled
 * \brief A global switch to enable all checksums for all protocols.
 */
static GlobalValue g_checksumEnabled  = GlobalValue ("ChecksumEnabled",
                                                     "A global switch to enable all checksums for all protocols",
                                                     BooleanValue (false),
                                                     MakeBooleanChecker ());

TypeId 
Node::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::Node")
    .SetParent<Object> ()
    .SetGroupName("Network")
    .AddConstructor<Node> ()
    .AddAttribute ("DeviceList", "The list of devices associated to this Node.",
                   ObjectVectorValue (),
                   MakeObjectVectorAccessor (&Node::m_devices),
                   MakeObjectVectorChecker<NetDevice> ())
    .AddAttribute ("ApplicationList", "The list of applications associated to this Node.",
                   ObjectVectorValue (),
                   MakeObjectVectorAccessor (&Node::m_applications),
                   MakeObjectVectorChecker<Application> ())
    .AddAttribute ("Id", "The id (unique integer) of this Node.",
                   TypeId::ATTR_GET, // allow only getting it.
                   UintegerValue (0),
                   MakeUintegerAccessor (&Node::m_id),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("SystemId", "The systemId of this node: a unique integer used for parallel simulations.",
                   TypeId::ATTR_GET | TypeId::ATTR_SET,
                   UintegerValue (0),
                   MakeUintegerAccessor (&Node::m_sid),
                   MakeUintegerChecker<uint32_t> ())
  ;
  return tid;
}

Node::Node()
  : m_id (0),
    m_sid (0)
{
  NS_LOG_FUNCTION (this);
  Construct ();
}

Node::Node(uint32_t sid)
  : m_id (0),
    m_sid (sid)
{ 
  NS_LOG_FUNCTION (this << sid);
  Construct ();
}

void
Node::Construct (void)
{
  NS_LOG_FUNCTION (this);
  m_id = NodeList::Add (this);
}

Node::~Node ()
{
  NS_LOG_FUNCTION (this);
}

uint32_t
Node::GetId (void) const
{
  NS_LOG_FUNCTION (this);
  return m_id;
}

Time
Node::GetLocalTime (void) const
{
  NS_LOG_FUNCTION (this);
  return Simulator::Now ();
}

uint32_t
Node::GetSystemId (void) const
{
  NS_LOG_FUNCTION (this);
  return m_sid;
}

uint32_t
Node::AddDevice (Ptr<NetDevice> device)
{
  NS_LOG_FUNCTION (this << device);
  uint32_t index = m_devices.size ();
  m_devices.push_back (device);
  device->SetNode (this);
  device->SetIfIndex (index);
  device->SetReceiveCallback (MakeCallback (&Node::NonPromiscReceiveFromDevice, this));
  Simulator::ScheduleWithContext (GetId (), Seconds (0.0), 
                                  &NetDevice::Initialize, device);
  NotifyDeviceAdded (device);
  return index;
}
Ptr<NetDevice>
Node::GetDevice (uint32_t index) const
{
  NS_LOG_FUNCTION (this << index);
  NS_ASSERT_MSG (index < m_devices.size (), "Device index " << index <<
                 " is out of range (only have " << m_devices.size () << " devices).");
  return m_devices[index];
}
uint32_t 
Node::GetNDevices (void) const
{
  NS_LOG_FUNCTION (this);
  return m_devices.size ();
}

uint32_t 
Node::AddApplication (Ptr<Application> application)
{
  NS_LOG_FUNCTION (this << application);
  uint32_t index = m_applications.size ();
  m_applications.push_back (application);
  application->SetNode (this);
  Simulator::ScheduleWithContext (GetId (), Seconds (0.0), 
                                  &Application::Initialize, application);
  return index;
}
Ptr<Application> 
Node::GetApplication (uint32_t index) const
{
  NS_LOG_FUNCTION (this << index);
  NS_ASSERT_MSG (index < m_applications.size (), "Application index " << index <<
                 " is out of range (only have " << m_applications.size () << " applications).");
  return m_applications[index];
}
uint32_t 
Node::GetNApplications (void) const
{
  NS_LOG_FUNCTION (this);
  return m_applications.size ();
}

void 
Node::DoDispose ()
{
  NS_LOG_FUNCTION (this);
  m_deviceAdditionListeners.clear ();
  m_handlers.clear ();
  for (std::vector<Ptr<NetDevice> >::iterator i = m_devices.begin ();
       i != m_devices.end (); i++)
    {
      Ptr<NetDevice> device = *i;
      device->Dispose ();
      *i = 0;
    }
  m_devices.clear ();
  for (std::vector<Ptr<Application> >::iterator i = m_applications.begin ();
       i != m_applications.end (); i++)
    {
      Ptr<Application> application = *i;
      application->Dispose ();
      *i = 0;
    }
  m_applications.clear ();
  Object::DoDispose ();
}
void 
Node::DoInitialize (void)
{
  NS_LOG_FUNCTION (this);
  for (std::vector<Ptr<NetDevice> >::iterator i = m_devices.begin ();
       i != m_devices.end (); i++)
    {
      Ptr<NetDevice> device = *i;
      device->Initialize ();
    }
  for (std::vector<Ptr<Application> >::iterator i = m_applications.begin ();
       i != m_applications.end (); i++)
    {
      Ptr<Application> application = *i;
      application->Initialize ();
    }

  Object::DoInitialize ();
}

void
Node::RegisterProtocolHandler (ProtocolHandler handler, 
                               uint16_t protocolType,
                               Ptr<NetDevice> device,
                               bool promiscuous)
{
  NS_LOG_FUNCTION (this << &handler << protocolType << device << promiscuous);
  struct Node::ProtocolHandlerEntry entry;
  entry.handler = handler;
  entry.protocol = protocolType;
  entry.device = device;
  entry.promiscuous = promiscuous;

  // On demand enable promiscuous mode in netdevices
  if (promiscuous)
    {
      if (device == 0)
        {
          for (std::vector<Ptr<NetDevice> >::iterator i = m_devices.begin ();
               i != m_devices.end (); i++)
            {
              Ptr<NetDevice> dev = *i;
              dev->SetPromiscReceiveCallback (MakeCallback (&Node::PromiscReceiveFromDevice, this));
            }
        }
      else
        {
          device->SetPromiscReceiveCallback (MakeCallback (&Node::PromiscReceiveFromDevice, this));
        }
    }

  m_handlers.push_back (entry);
}

void
Node::UnregisterProtocolHandler (ProtocolHandler handler)
{
  NS_LOG_FUNCTION (this << &handler);
  for (ProtocolHandlerList::iterator i = m_handlers.begin ();
       i != m_handlers.end (); i++)
    {
      if (i->handler.IsEqual (handler))
        {
          m_handlers.erase (i);
          break;
        }
    }
}

bool
Node::ChecksumEnabled (void)
{
  NS_LOG_FUNCTION_NOARGS ();
  BooleanValue val;
  g_checksumEnabled.GetValue (val);
  return val.Get ();
}

bool
Node::PromiscReceiveFromDevice (Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol,
                                const Address &from, const Address &to, NetDevice::PacketType packetType)
{
  NS_LOG_FUNCTION (this << device << packet << protocol << &from << &to << packetType);
  return ReceiveFromDevice (device, packet, protocol, from, to, packetType, true);
}

bool
Node::NonPromiscReceiveFromDevice (Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol,
                                   const Address &from)
{
  NS_LOG_FUNCTION (this << device << packet << protocol << &from);
  return ReceiveFromDevice (device, packet, protocol, from, device->GetAddress (), NetDevice::PacketType (0), false);
}

bool
Node::ReceiveFromDevice (Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol,
                         const Address &from, const Address &to, NetDevice::PacketType packetType, bool promiscuous)
{
  NS_LOG_FUNCTION (this << device << packet << protocol << &from << &to << packetType << promiscuous);
  NS_ASSERT_MSG (Simulator::GetContext () == GetId (), "Received packet with erroneous context ; " <<
                 "make sure the channels in use are correctly updating events context " <<
                 "when transferring events from one node to another.");
  NS_LOG_DEBUG ("Node " << GetId () << " ReceiveFromDevice:  dev "
                        << device->GetIfIndex () << " (type=" << device->GetInstanceTypeId ().GetName ()
                        << ") Packet UID " << packet->GetUid ());
  bool found = false;

  for (ProtocolHandlerList::iterator i = m_handlers.begin ();
       i != m_handlers.end (); i++)
    {
      if (i->device == 0 ||
          (i->device != 0 && i->device == device))
        {
          if (i->protocol == 0 || 
              i->protocol == protocol)
            {
              if (promiscuous == i->promiscuous)
                {
                  i->handler (device, packet, protocol, from, to, packetType);
                  found = true;
                }
            }
        }
    }
  return found;
}
void 
Node::RegisterDeviceAdditionListener (DeviceAdditionListener listener)
{
  NS_LOG_FUNCTION (this << &listener);
  m_deviceAdditionListeners.push_back (listener);
  // and, then, notify the new listener about all existing devices.
  for (std::vector<Ptr<NetDevice> >::const_iterator i = m_devices.begin ();
       i != m_devices.end (); ++i)
    {
      listener (*i);
    }
}
void 
Node::UnregisterDeviceAdditionListener (DeviceAdditionListener listener)
{
  NS_LOG_FUNCTION (this << &listener);
  for (DeviceAdditionListenerList::iterator i = m_deviceAdditionListeners.begin ();
       i != m_deviceAdditionListeners.end (); i++)
    {
      if ((*i).IsEqual (listener))
        {
          m_deviceAdditionListeners.erase (i);
          break;
         }
    }
}
 
void 
Node::NotifyDeviceAdded (Ptr<NetDevice> device)
{
  NS_LOG_FUNCTION (this << device);
  for (DeviceAdditionListenerList::iterator i = m_deviceAdditionListeners.begin ();
       i != m_deviceAdditionListeners.end (); i++)
    {
      (*i) (device);
    }  
}


/**
 * @brief Register one node as neighbor in node's neighbor list
 * 
 * @param ip Neighbor node IPv4 address
 * @param position Neighbor node position (x, y, z)
 * @param distance Neighbor node distance from node
 * @param attitude Neighbor node attitude (0 - keep distance, 1 - inbound, 2 - outbound)
 * @param quality Neighbor node presence (3 - Connected, 2 - Lost connection 1, 1 - Lost connection 2, 0 - Lost)
 * @param hop Neighbor hop
 * @param state Neighbor state (0 ordinary, 1 malicious)
 */

void
Node::RegisterNeighbor (Ipv4Address ip, Vector position, double distance, uint8_t attitude, uint8_t quality, uint8_t hop, uint8_t state) //, double time)
{
  NS_LOG_FUNCTION (this);
  struct Node::Neighbor neighbor;

  neighbor.ip = ip;
  neighbor.position = position;
  neighbor.distance = distance;
  neighbor.attitude = attitude;
  neighbor.quality = quality;
  neighbor.hop = hop;
  neighbor.state = state;
  //neighbor.infoTime = time;
  m_neighborList.push_back (neighbor);
}


/**
 * @brief Get node's neighbors IP addresses
 * 
 * @return std::vector<Ipv4Address> - List with node's neighbor IP addresses
 */

std::vector<Ipv4Address>
Node::GetNeighborIpList ()
{
  NS_LOG_FUNCTION (this);
  std::vector<Ipv4Address> NeighborIpList;
  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end (); i++)
    {
      NeighborIpList.push_back (i->ip);
    }
  return NeighborIpList;
}


/**
 * @brief Remove a node from nodes' neighbor list
 * @param ip Neighbor IP address
 */
void
Node::UnregisterNeighbor (Ipv4Address ip)
{
  NS_LOG_FUNCTION (this);
  if (IsAlreadyNeighbor (ip)) // checks if is already a neighbor
    {
      for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end ();
           i++)
        {
          if (i->ip == ip)
            {
              m_neighborList.erase (i);
              break;
            }
        }
    }
}


/**
 * @brief Update the position of a neighbor node
 * 
 * @date Nov 10, 2022
 */
void
Node::UpdateNeighbor (Ipv4Address ip, Vector position, double distance, 
                      uint8_t attitude, uint8_t quality, uint8_t hop) //, uint8_t state) //, double time)
{
  NS_LOG_FUNCTION (this);
  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end ();
        i++)
    {
      if (i->ip == ip)
        {
          (*i).position = position; 
          (*i).distance = distance; 
          (*i).attitude = attitude; 
          (*i).quality = quality;
          (*i).hop = hop;
          //(*i).state = state;     
          //(*i).infoTime = time;          
          break;
        }
    }
}


/**
 * @brief Get the position of a neighbor node
 * @date Nov 11, 2022
 */
Vector
Node::GetNeighborPosition (Ipv4Address ip)
{
  Vector position;
  NS_LOG_FUNCTION (this);
  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end (); i++)
    {
      if (i->ip == ip) 
      {
        position = i->position; 
        break;
      }
    }
  return position;
}


/**
 * @brief Get the distance of a neighbor node
 * @date Dez 29, 2022
 * 
 * @param ip - Neighbor node IPv4 address
 * @return double - Neighbor node old distance
 */
double
Node::GetNeighborDistance (Ipv4Address ip)
{
  double distance;
  NS_LOG_FUNCTION (this);
  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end (); i++)
    {
      if (i->ip == ip) 
      {
        distance = i->distance; 
        break;
      }
    }
  return distance;
}


/**
 * @brief Get the attitude of a neighbor node
 * @date Dez 29, 2022
 * 
 * @param ip - Neighbor node IPv4 address
 * @return uint8_t - Neighbor node attitude
 */
uint8_t
Node::GetNeighborAttitude (Ipv4Address ip)
{
  uint8_t attitude;
  NS_LOG_FUNCTION (this);
  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end (); i++)
    {
      if (i->ip == ip) 
      {
        attitude = i->attitude; 
        break;
      }
    }
  return attitude;
}


/**
 * @brief Set the attitude of a neighbor node
 * @date Jan 2, 2023
 * 
 * @param ip - Neighbor node IPv4 address
 * @param attitude - Neighbor node new attitude
 */
void
Node::SetNeighborAttitude (Ipv4Address ip, u_int8_t attitude)
{
  NS_LOG_FUNCTION (this);
  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end (); i++)
    {
      if (i->ip == ip) 
      {
        i->attitude = attitude; 
        break;
      }
    }
}


/**
 * @brief Get the quality of a neighbor node
 * @date Dez 29, 2022
 * 
 * @param ip - Neighbor node IPv4 address
 * @return uint8_t - Neighbor node quality
 */
uint8_t
Node::GetNeighborQuality (Ipv4Address ip)
{
  uint8_t quality;
  NS_LOG_FUNCTION (this);
  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end (); i++)
    {
      if (i->ip == ip) 
      {
        quality = i->quality; 
        break;
      }
    }
  return quality;
}

/**
 * @brief Set the quality of a neighbor node
 * @date jan 2, 2023
 * 
 * @param ip - Neighbor node IPv4 address
 * @param quality - Neighbor node new quality
 */
void
Node::SetNeighborQuality (Ipv4Address ip, uint8_t quality)
{
  NS_LOG_FUNCTION (this);
  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end (); i++)
    {
      if (i->ip == ip) 
      {
        i->quality = quality; 
        break;
      }
    }
}


/**
 * @brief Get the hop of a neighbor node
 * @date Mar 5, 2023
 * 
 * @param ip - Neighbor node IPv4 address
 * @return uint8_t - Neighbor node hop
 */
uint8_t
Node::GetNeighborHop (Ipv4Address ip)
{
  uint8_t hop;
  NS_LOG_FUNCTION (this);
  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end (); i++)
    {
      if (i->ip == ip) 
      {
        hop = i->hop; 
        break;
      }
    }
  return hop;
}

/**
 * @brief Set the hop of a neighbor node
 * @date Mar 5, 2023
 * 
 * @param ip - Neighbor node IPv4 address
 * @param hop - Neighbor node new hop
 */
void
Node::SetNeighborHop (Ipv4Address ip, uint8_t hop)
{
  NS_LOG_FUNCTION (this);
  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end (); i++)
    {
      if (i->ip == ip) 
      {
        i->hop = hop; 
        break;
      }
    }
}

/**
 * @brief Get a neighbor node state
 * @date Oct 23, 2023
 * 
 * @param ip - Neighbor node IPv4 address
 * @return bool - Neighbor node state (0 ordinary, 1 malicious)
 */
uint8_t
Node::GetNeighborNodeState (Ipv4Address ip)
{
  uint8_t state;
  NS_LOG_FUNCTION (this);
  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end (); i++)
    {
      if (i->ip == ip) 
      {
        state = i->state; 
        break;
      }
    }
  return state;
}

/**
 * @brief Set a neighbor node state
 * @date Oct 23, 2023
 * 
 * @param ip - Neighbor node IPv4 address
 * @param state - Neighbor node state (0 ordinary, 1 malicious)
 */
void
Node::SetNeighborNodeState (Ipv4Address ip, uint8_t state)
{
  NS_LOG_FUNCTION (this);
  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end (); i++)
    {
      if (i->ip == ip) 
      {
        i->state = state; 
        break;
      }
    }
}

/**
 * @brief information of a neighbor node
 * @date Mar 5, 2023
 * 
 * @param ip - Neighbor node IPv4 address
 * @return uint8_t - Neighbor node information time
 */

/*
double
Node::GetNeighborInfoTime (Ipv4Address ip)
{
  double time;
  NS_LOG_FUNCTION (this);
  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end (); i++)
    {
      if (i->ip == ip) 
      {
        time = i->infoTime; 
        break;
      }
    }
  return time;
}
*/


/**
 * @brief Set the information time of a neighbor node
 * @date Mar 5, 2023
 * 
 * @param ip - Neighbor node IPv4 address
 * @param hop - Neighbor node new information Time
 */
/*
void
Node::SetNeighborInfoTime (Ipv4Address ip, double time)
{
  NS_LOG_FUNCTION (this);
  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end (); i++)
    {
      if (i->ip == ip) 
      {
        i->infoTime = time; 
        break;
      }
    }
}
 */

/**
 * @brief Verify if node has neighbors
 * 
 * @return true - Node has neighbors
 * @return false - Node has no neighbors
 */
bool
Node::IsThereAnyNeighbor ()
{
  NS_LOG_FUNCTION (this);
  return !m_neighborList.empty ();
}


/**
 * @brief Verify if there is at least one 1 hop in NL
 * 
 * @return true - Node has a 1 hop neighbor
 * @return false - Node has no 1 hop neighbors
 */
bool
Node::IsThereAnyNeighbor (uint8_t hop)
{
  NS_LOG_FUNCTION (this);
  bool inTheList = false;

  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end (); i++)
    if (i->hop == hop)
      {
        inTheList = true;
        break;
      }
  return inTheList;
}


/**
 * @brief Verify if a node is neighbor of this one
 * 
 * @param ip Node IPv4 address
 * @return true - Node is already a neighbor
 * @return false - Node is not a neigbhor yet
 */

bool
Node::IsAlreadyNeighbor (Ipv4Address ip)
{
  NS_LOG_FUNCTION (this);
  bool inTheList = false;

  for (NeighborHandlerList::iterator i = m_neighborList.begin (); i != m_neighborList.end (); i++)
    if (i->ip == ip)
      {
        inTheList = true;
        break;
      }
  return inTheList;
}

/**
 * @brief Get the number of node's neighbors
 * 16Nov18
 * 
 * @return int - Number of node's neighbors
 */

int
Node::GetNNeighbors (void)
{
  NS_LOG_FUNCTION (this);
  return (int) m_neighborList.size ();
}


/**
 * @brief Clean the neighbor list
 * @date Mar 10, 2023
 */

void
Node::ClearNeighborList ()
{
  NS_LOG_FUNCTION (this);
  m_neighborList.clear();
}

/**
 * @brief Get nodes position (x,y,z)
 * 26Sep2022
 * 
 * @return Vector - Nodes position (x,y,z)
 */

Vector
Node::GetPosition()
{
  NS_LOG_FUNCTION (this);
  return(m_position);
}


/**
 * @brief Check whether the node is moving
 * 26Sep2022
 * 
 * @param position - Vector with actual node position
 * @return true - Node is moving
 * @return false - Node is stopped
 */

bool
Node::IsMoving (Vector position)
{
  NS_LOG_FUNCTION (this);
  return (m_position.x != position.x) || (m_position.y != position.y) || (m_position.z != position.z);
}


/**
 * @brief Set nodes position (x,y,z)
 * 26Sep2022
 * 
 * @param position - Vector with coordinates
 */

void
Node::SetPosition(Vector position)
{
  NS_LOG_FUNCTION (this);
  m_position = position;
}

/**
 * @brief Get nodes state
 * @date Oct 23, 2023
 * 
 * @return u_int8_t - node state (0 ordinary, 1 malicious)
 */

u_int8_t
Node::GetState()
{
  NS_LOG_FUNCTION (this);
  return(m_state);
}


/**
 * @brief Set node state (0 ordinary, 1 malicious)
 * @date Oct 23, 2023
 * 
 * @param state - node state (0 ordinary, 1 malicious)
 */
void
Node::SetState(u_int8_t state)
{
  NS_LOG_FUNCTION (this);
  m_state = state;
}

// ---------------------------------------------------------------------
// Methods for control malicious neighbor nodes
// (Suspect or blocked)
// ---------------------------------------------------------------------

/**
 * @brief Register a neighbor node in the malicious list
 * @date Oct 23, 2023
 * 
 * @param ip IPv4 from malicious node 
 * @param notifyIP IPv4 from notifier node
 */
void
Node::RegisterMaliciousNode (Ipv4Address ip, Ipv4Address notifyIP)
{
  NS_LOG_FUNCTION (this);
  struct Node::MaliciousNode maliciousNeighbor;

  maliciousNeighbor.ip = ip;
  maliciousNeighbor.state = 0;
  maliciousNeighbor.recurrence = 1;
  maliciousNeighbor.notifyIP.push_back(notifyIP);
  m_MaliciousNodeList.push_back (maliciousNeighbor);
}

/**
 * @brief Remove a neighbor node from the malicious list
 * @date Oct 23, 2023
 * 
 * @param ip IPv4 from malicious node 
 */
void
Node::UnregisterMaliciousNode (Ipv4Address ip)
{
  NS_LOG_FUNCTION (this);
  if (IsAMaliciousNode (ip)) // checks if is already a neighbor
    {
      for (MaliciousNodeHandlerList::iterator i = m_MaliciousNodeList.begin (); i != m_MaliciousNodeList.end ();
           i++)
        {
          if (i->ip == ip)
            {
              m_MaliciousNodeList.erase (i);
              break;
            }
        }
    }
}

/**
 * @brief Get a malicious node recurrence
 * @date Oct 23, 2023
 * 
 * @param ip - Malicious node IPv4 address
 * @return uint8_t - Neighbor node recurrence
 */
uint8_t
Node::GetMaliciousNodeRecurrence (Ipv4Address ip)
{
  u_int8_t recurrence;
  NS_LOG_FUNCTION (this);
  for (MaliciousNodeHandlerList::iterator i = m_MaliciousNodeList.begin (); i != m_MaliciousNodeList.end (); i++)
    {
      if (i->ip == ip) 
      {
        recurrence = i->recurrence; 
        break;
      }
    }
  return recurrence;
}

/**
 * @brief Increase a malicious node recurrence
 * @date Oct 23, 2023
 * 
 * @param ip - Malicious node IPv4 address
 */
void
Node::IncreaseMaliciousNodeRecurrence (Ipv4Address ip, Ipv4Address notifyIP)
{
  NS_LOG_FUNCTION (this);
  for (MaliciousNodeHandlerList::iterator i = m_MaliciousNodeList.begin (); i != m_MaliciousNodeList.end (); i++)
    {
      if (i->ip == ip) 
      {
        i->recurrence += 1; 
        i->notifyIP.push_back(notifyIP);
        break;
      }
    }
}


/**
 * @brief Decrease a malicious node recurrence
 * @date Nov 2, 2023
 * 
 * @param ip - Malicious node IPv4 address
 * @param notifyIP IPv4 address from notifier node
 */
void
Node::DecreaseMaliciousNodeRecurrence (Ipv4Address ip, Ipv4Address notifyIP)
{
  NS_LOG_FUNCTION (this);
  MaliciousNodeHandlerList::iterator i;
  std::vector<ns3::Ipv4Address>::const_iterator beginIt;
  
  for (i = m_MaliciousNodeList.begin (); i != m_MaliciousNodeList.end (); i++)
    {
    if (i->ip == ip) {
      beginIt = i->notifyIP.begin();
      for (int n = 0; n < (int)i->notifyIP.size(); n++){
        if (i->notifyIP[n] == notifyIP) {
            i->recurrence -= 1;
            i->notifyIP.erase(beginIt + n);
        break;
        }
      }
      break;
    }
  }
}


// void
// Node::DecreaseMaliciousNodeRecurrence (Ipv4Address ip, Ipv4Address notifyIP)
// {
//   NS_LOG_FUNCTION (this);
//   for (MaliciousNodeHandlerList::iterator i = m_MaliciousNodeList.begin (); i != m_MaliciousNodeList.end (); i++)
//     {
//       if (i->ip == ip) 
//       {
//         if (i->recurrence > 0){
//           i->recurrence -= 1; 
//         }
//         break;
//       }
//     }
// }

/**
 * @brief Get a malicious node state (0 suspect, 1 Blocked)
 * @date Oct 23, 2023
 * 
 * @param ip - Malicious node IPv4 address
 * @return uint8_t - 0 (suspect)
 * @return uint8_t - 1 (blocked)
 */
uint8_t
Node::GetMaliciousNodeState (Ipv4Address ip)
{
  uint8_t state;
  NS_LOG_FUNCTION (this);
  for (MaliciousNodeHandlerList::iterator i = m_MaliciousNodeList.begin (); i != m_MaliciousNodeList.end (); i++)
    {
      if (i->ip == ip) 
      {
        state = i->state; 
        break;
      }
    }
  return state;
}

/**
 * @brief Set a malicious node state (0 suspect, 1 Blocked)
 * @date Oct 23, 2023
 * 
 * @param ip - Malicious node IPv4 address
 * @param state - Malicious node state (0 suspect, 1 Blocked)
 */
void
Node::SetMaliciousNodeState (Ipv4Address ip, uint8_t state)
{
  NS_LOG_FUNCTION (this);
  for (MaliciousNodeHandlerList::iterator i = m_MaliciousNodeList.begin (); i != m_MaliciousNodeList.end (); i++)
    {
      if (i->ip == ip) 
      {
        i->state = state; 
        break;
      }
    }
}

/**
 * @brief Verify if there are known malicious nodes 
 * @date Oct 23, 2023
 * 
 * @return true - Node knows malicious nodes
 * @return false - Node doesn't know malicious nodes
 */
bool
Node::IsThereAnyMaliciousNode ()
{
  NS_LOG_FUNCTION (this);
  return !m_MaliciousNodeList.empty ();
}

/**
 * @brief Get a IPv4 list of known malicious nodes 
 * @date Oct 23, 2023
 * 
 * @return vector - IPv4 list with known malicious nodes
 */
std::vector<Ipv4Address>
Node::GetMaliciousNodeIpList ()
{
  NS_LOG_FUNCTION (this);
  std::vector<Ipv4Address> MaliciousIpList;
  for (MaliciousNodeHandlerList::iterator i = m_MaliciousNodeList.begin (); i != m_MaliciousNodeList.end (); i++)
    {
      MaliciousIpList.push_back (i->ip);
    }
  return MaliciousIpList;
}


/**
 * @brief Get a malicious nodes notifiers IP address 
 * 
 * @date Nov 23, 2023
 * 
 * @param maliciousNode Malicious node IPv4
 * @return std::vector<Ipv4Address> - Vector with malicious nodes notifiers IP address 
 */
std::vector<Ipv4Address>
Node::GetMaliciousNodesIPNotifiers (Ipv4Address maliciousNode)
{
  NS_LOG_FUNCTION (this);
  std::vector<Ipv4Address> notifiers;
  for (MaliciousNodeHandlerList::iterator i = m_MaliciousNodeList.begin (); i != m_MaliciousNodeList.end (); i++)
    {
      if (i->ip == maliciousNode){
        for (int n = 0; n < (int)i->notifyIP.size(); n++) {
          notifiers.push_back(i->notifyIP[n]);
        }
      }
    }
  return notifiers;
}



/**
 * @brief Verify wether a node is already known as malicious 
 * @date Oct 23, 2023
 * 
 * @param ip - node IPv4 address 
 * @return false - Node is not known as malicious
 * @return true - Node is already known as malicious
 */
bool
Node::IsAMaliciousNode (Ipv4Address ip)
{
  NS_LOG_FUNCTION (this);
  bool inTheList = false;

  for (MaliciousNodeHandlerList::iterator i = m_MaliciousNodeList.begin (); i != m_MaliciousNodeList.end (); i++)
    if (i->ip == ip)
      {
        inTheList = true;
        break;
      }
  return inTheList;
}


/**
 * @brief Verify wether a malicious node is already blocked 
 * @date Oct 23, 2023
 * 
 * @param ip - node IPv4 address 
 * @return false - Suspect
 * @return true - Blocked
 */
bool
Node::IsABlockedNode (Ipv4Address ip)
{
  NS_LOG_FUNCTION (this);
  bool blocked = false;

  for (MaliciousNodeHandlerList::iterator i = m_MaliciousNodeList.begin (); i != m_MaliciousNodeList.end (); i++)
    if (i->ip == ip)
      {
        if (i->state == 1)
          {
          blocked = true;
          }
      }
  return blocked;
}

/**
 * @brief Get the amount of known malicious nodes in the list
 * @date Oct 23, 2023
 * 
 * @return uint8_t - Number of malicious nodes
 */
uint8_t
Node::GetNMaliciousNodes (void)
{
  NS_LOG_FUNCTION (this);
  return (int) m_MaliciousNodeList.size ();
}

/**
 * @brief Clear malicious nodes list
 * @date Oct 23, 2023
 */
void
Node::ClearMaliciousNodeList ()
{
  NS_LOG_FUNCTION (this);
  m_MaliciousNodeList.clear();
}


} // namespace ns3
