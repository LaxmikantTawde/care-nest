const createBabyProfile = async (babyData) => {
    const response = await fetch('http://10.0.2.2:5000/api/babies', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(babyData),
    });
  
    if (!response.ok) {
      throw new Error('Failed to create baby profile');
    }
  
    return await response.json(); // Assuming your backend returns the created baby profile, including the babyId
  };
  