import React from 'react';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { Image, StyleSheet } from 'react-native';

// Import the screen components
import HomeScreen from './Home';
import Setting from './Mealplan';
import ProfileScreen from './Meallist';
import NotificationsScreen from './search';

const Tab = createBottomTabNavigator();

const BottomTabNavigator = () => {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: ({ focused }) => {
          let iconSource;

          // Assign each tab an icon image
          if (route.name === 'Home1') {
            iconSource = require('./home.png');
          } else if (route.name === 'Settings') {
            iconSource = require('./meal.png');
          } else if (route.name === 'Profile') {
            iconSource = require('./search.png');
          } else if (route.name === 'Notifications') {
            iconSource = require('./bar.png');
          }

          // Return the icon as an Image component
          return (
            <Image
              source={iconSource}
              style={[
                styles.icon,
                { tintColor: focused ? 'black' : 'gray' } // Change color based on focus
              ]}
              resizeMode="contain"
            />
          );
        },
        tabBarShowLabel: false, // Hide the label text
        tabBarActiveTintColor: 'black', // Active icon color
        tabBarInactiveTintColor: 'gray', // Inactive icon color
        tabBarStyle: styles.tabBar, // Custom style for the tab bar
        headerShown: false, // Hide header
      })}
    >
      <Tab.Screen name="Home1" component={HomeScreen} />
      <Tab.Screen name="Settings" component={Setting} />
      <Tab.Screen name="Profile" component={ProfileScreen} />
      <Tab.Screen name="Notifications" component={NotificationsScreen} />
    </Tab.Navigator>
  );
};

const styles = StyleSheet.create({
  icon: {
    width: 24, // Icon width to match provided design
    height: 24, // Icon height to match provided design
  },
  tabBar: {
    backgroundColor: '#ffffff', // Light gray background color
    position: 'absolute',
    bottom: 10, // Space from bottom
    left: 20, // Space from left
    right: 20, // Space from right
    height: 60, // Height to create a "cut" effect
    borderRadius: 30, // Full rounded edges on the tab bar
    borderColor: 'white', // White border for separation
    borderWidth: 1,
    shadowColor: '#000000', // Shadow for elevation effect
    shadowOffset: { width: 0, height: 3 },
    shadowOpacity: 0.25,
    shadowRadius: 5,
    elevation: 5,
  },
});

export default BottomTabNavigator;
