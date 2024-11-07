import React, { useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet } from 'react-native';

const AccountSettings = () => {
  const [name, setName] = useState('');
  const [mobile, setMobile] = useState('');
  const [email, setEmail] = useState('');

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerText}>Account Settings</Text>
      </View>

      {/* Form Fields */}
      <View style={styles.inputContainer}>
        <Text style={styles.label}>Your Name</Text>
        <View style={styles.inputWrapper}>
          <TextInput
            style={styles.input}
            placeholder="Enter your name"
            value={name}
            onChangeText={setName}
          />
          <TouchableOpacity style={styles.editIcon}>
            <Text style={styles.iconText}>✎</Text>
          </TouchableOpacity>
        </View>
      </View>

      <View style={styles.inputContainer}>
        <Text style={styles.label}>Mobile Number</Text>
        <View style={styles.inputWrapper}>
          <TextInput
            style={styles.input}
            placeholder="Enter your mobile number"
            value={mobile}
            onChangeText={setMobile}
          />
          <TouchableOpacity style={styles.editIcon}>
            <Text style={styles.iconText}>✎</Text>
          </TouchableOpacity>
        </View>
      </View>

      <View style={styles.inputContainer}>
        <Text style={styles.label}>Email ID</Text>
        <View style={styles.inputWrapper}>
          <TextInput
            style={styles.input}
            placeholder="Enter your email ID"
            value={email}
            onChangeText={setEmail}
          />
        </View>
      </View>

      {/* Save Changes Button */}
      <TouchableOpacity style={styles.saveButton}>
        <Text style={styles.saveButtonText}>Save Changes</Text>
      </TouchableOpacity>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    backgroundColor: '#FFFFFF', // Background color
  },
  header: {
    backgroundColor: '#6EBE77', // Header color
    paddingVertical: 20,
    alignItems: 'center',
    borderRadius: 10,
    marginBottom: 20,
    shadowColor: '#000', // Shadow for depth
    shadowOffset: {
      width: 0,
      height: 2,
    },
    shadowOpacity: 0.3,
    shadowRadius: 4,
    elevation: 5,
  },
  headerText: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#FFFFFF', // Header text color
  },
  inputContainer: {
    marginBottom: 20,
  },
  label: {
    fontSize: 16,
    marginBottom: 5,
    color: '#333', // Darker label color
  },
  inputWrapper: {
    flexDirection: 'row',
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#BDBDBD',
    borderRadius: 10,
    backgroundColor: '#F7F7F7', // Light background for input
    overflow: 'hidden', // Rounded corners
  },
  input: {
    flex: 1,
    height: 50,
    paddingLeft: 15,
    fontSize: 16,
    borderColor: 'transparent', // Hide border from input
  },
  editIcon: {
    padding: 10,
    backgroundColor: '#E0E0E0', // Background for edit icon
    borderRadius: 10,
  },
  iconText: {
    fontSize: 18,
    color: '#555', // Color for edit icon
  },
  saveButton: {
    backgroundColor: '#6EBE77', // Button color
    padding: 15,
    borderRadius: 10,
    alignItems: 'center',
    shadowColor: '#000',
    shadowOffset: {
      width: 0,
      height: 2,
    },
    shadowOpacity: 0.3,
    shadowRadius: 4,
    elevation: 5,
  },
  saveButtonText: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#FFFFFF', // Button text color
  },
});

export default AccountSettings;
