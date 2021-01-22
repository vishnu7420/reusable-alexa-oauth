'use strict';
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('user_refresh_tokens', {
      id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: Sequelize.INTEGER
      },
      user_id: {
        allowNull: false,
        type: Sequelize.INTEGER,
        onDelete: 'CASCADE',
        onUpdate: 'RESTRICT',
        references: {
          model: 'users',
          key: 'id'
        },
      },
      token: {
        allowNull: false,
        type: Sequelize.STRING,
      },
      expires: {
        allowNull: false,
        type: Sequelize.DATE
      },
      createdByIp: {
        allowNull: false,
        type: Sequelize.STRING,
      },
      revoked: {
        allowNull: true,
        type: Sequelize.DATE
      },
      revokedByIp: {
        allowNull: true,
        type: Sequelize.STRING
      },
      replacedByToken: {
        allowNull: true,
        type: Sequelize.STRING
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')


      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP')
      }
    });
  },
  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('user_refresh_tokens');
  }
};

